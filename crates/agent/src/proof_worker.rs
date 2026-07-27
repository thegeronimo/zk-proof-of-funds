//! Proof Workers — generates EIP-712 signatures (trusted mode) or SP1 batch proofs (ZK mode).
//!
//! In trusted mode (Phase 1): signs an EIP-712 typed data assertion with the operator key.
//! In ZK mode (Phase 2): loads the SP1 ELF binary, constructs stdin, generates Groth16 proof.
//!
//! ## ZK Mode Architecture
//!
//! The SP1 program (program/src/main.rs) reads inputs via `sp1_zkvm::io::read()` (bincode):
//!   Global: state_root, policy_id, epoch, threshold_wei, block_number, chain_id, member_count
//!   Per-member: member_id, watch_target, proof_nodes (MPT proof)
//!
//! It commits public outputs via `sp1_zkvm::io::commit()` (bincode):
//!   state_root, policy_id, epoch, solvency_root, threshold_wei, member_count, block_number, chain_id
//!
//! The Solidity contract expects ABI-encoded public values:
//!   abi.decode(publicValues, (bytes32, bytes32, uint64, bytes32, uint64, uint32, uint64, uint64))
//!
//! The host must re-encode from bincode → ABI for on-chain submission.

use anyhow::{Context, Result};
use alloy::primitives::{Address, FixedBytes};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolStruct, SolValue, eip712_domain};
use alloy::sol;
use sp1_sdk::blocking::{Elf, ProverClient, Prover, ProveRequest, SP1Stdin};
use tracing::info;

// Define the EIP-712 struct for trusted mode solvency assertion.
// This must match the Solidity struct in SolvencyRootOracle.sol.
sol! {
    #[derive(Debug)]
    struct SolvencyRootUpdate {
        bytes32 policyId;
        bytes32 root;
        uint64 epoch;
        uint64 blockNumber;
        uint32 memberCount;
        uint64 chainId;
    }
}

/// Result of EIP-712 signing for trusted mode.
#[derive(Debug, Clone)]
pub struct TrustedModeSignature {
    /// The EIP-712 signature (65 bytes: r + s + v).
    pub signature: Vec<u8>,
    /// The signer's address.
    pub signer: [u8; 20],
}

/// Proof worker for generating attestations.
pub struct ProofWorker {
    /// Operator's private key signer (for trusted mode EIP-712 signing).
    operator_signer: PrivateKeySigner,
    /// Chain ID for EIP-712 domain.
    chain_id: u64,
    /// Oracle contract address for EIP-712 domain.
    oracle_address: Address,
}

impl ProofWorker {
    /// Create a new proof worker with the operator's private key.
    pub fn new(
        operator_private_key_hex: &str,
        chain_id: u64,
        oracle_address: &str,
    ) -> Result<Self> {
        let key_hex = operator_private_key_hex.strip_prefix("0x")
            .unwrap_or(operator_private_key_hex);

        let operator_signer: PrivateKeySigner = key_hex.parse()
            .context("Invalid operator private key")?;

        let oracle_address: Address = oracle_address.parse()
            .context("Invalid oracle address")?;

        info!(
            operator = %operator_signer.address(),
            chain_id = chain_id,
            "ProofWorker initialized for trusted mode"
        );

        Ok(Self {
            operator_signer,
            chain_id,
            oracle_address,
        })
    }

    /// Sign an EIP-712 solvency root assertion (trusted mode).
    ///
    /// This is used when the policy has `trusted_mode = true`.
    /// The operator signs a typed data structure attesting to the Merkle root
    /// for this epoch, and the on-chain contract verifies the signature
    /// comes from the authorized operator.
    pub async fn sign_trusted_assertion(
        &self,
        policy_id: &[u8; 32],
        root: &[u8; 32],
        epoch: u64,
        block_number: u64,
        member_count: u32,
    ) -> Result<TrustedModeSignature> {
        use alloy::signers::Signer;

        // Build the EIP-712 domain
        let domain = eip712_domain! {
            name: "SolvencyRootOracle",
            version: "1",
            chain_id: self.chain_id,
            verifying_contract: self.oracle_address,
        };

        // Build the EIP-712 struct
        let update = SolvencyRootUpdate {
            policyId: FixedBytes::from(*policy_id),
            root: FixedBytes::from(*root),
            epoch,
            blockNumber: block_number,
            memberCount: member_count,
            chainId: self.chain_id,
        };

        // Compute the EIP-712 signing hash
        let signing_hash = update.eip712_signing_hash(&domain);

        // Sign with the operator key
        let signature = self.operator_signer.sign_hash(&signing_hash).await
            .context("Failed to sign EIP-712 assertion")?;

        // Encode as 65 bytes: r (32) + s (32) + v (1)
        let sig_bytes = {
            let mut bytes = Vec::with_capacity(65);
            bytes.extend_from_slice(&signature.r().to_be_bytes::<32>());
            bytes.extend_from_slice(&signature.s().to_be_bytes::<32>());
            bytes.push(if signature.v() { 28 } else { 27 });
            bytes
        };

        let mut signer_addr = [0u8; 20];
        signer_addr.copy_from_slice(self.operator_signer.address().as_slice());

        info!(
            epoch = epoch,
            block_number = block_number,
            member_count = member_count,
            root = %hex::encode(root),
            signer = %self.operator_signer.address(),
            "Signed trusted mode assertion"
        );

        Ok(TrustedModeSignature {
            signature: sig_bytes,
            signer: signer_addr,
        })
    }

    /// Get the operator's address.
    pub fn operator_address(&self) -> Address {
        self.operator_signer.address()
    }
}

// ─── ZK Mode: SP1 Batch Proof Generation ─────────────────────────────────────

/// Input for a single member in the SP1 batch program.
#[derive(Debug, Clone)]
pub struct MemberProofInput {
    /// SHA-256 member ID (32 bytes).
    pub member_id: [u8; 32],
    /// Ethereum address being watched (20 bytes).
    pub watch_target: [u8; 20],
    /// RLP-encoded MPT proof nodes from eth_getProof.
    pub proof_nodes: Vec<Vec<u8>>,
}

/// Global inputs for an SP1 batch solvency proof.
#[derive(Debug, Clone)]
pub struct BatchProofInputs {
    /// Ethereum state root from the block header.
    pub state_root: [u8; 32],
    /// Policy ID (32 bytes).
    pub policy_id: [u8; 32],
    /// Epoch number.
    pub epoch: u64,
    /// Solvency threshold in wei (fits in u64 for now).
    pub threshold_wei: u64,
    /// Block number at which proofs were fetched.
    pub block_number: u64,
    /// Chain ID (e.g., 1 for mainnet).
    pub chain_id: u64,
    /// Per-member inputs with MPT proofs.
    pub members: Vec<MemberProofInput>,
}

/// Result of SP1 proof generation or execution.
#[derive(Debug, Clone)]
pub struct ZkProofResult {
    /// Groth16 proof bytes for on-chain verification (empty for execute-only mode).
    pub proof_bytes: Vec<u8>,
    /// ABI-encoded public values matching the Solidity contract's expected format.
    pub public_values_abi: Vec<u8>,
    /// The computed solvency Merkle root (extracted from SP1 public values).
    pub solvency_root: [u8; 32],
    /// The state root committed by the program.
    pub state_root: [u8; 32],
    /// Policy ID committed by the program.
    pub policy_id: [u8; 32],
    /// Epoch committed by the program.
    pub epoch: u64,
    /// Threshold committed by the program.
    pub threshold_wei: u64,
    /// Member count committed by the program.
    pub member_count: u32,
    /// Block number committed by the program.
    pub block_number: u64,
    /// Chain ID committed by the program.
    pub chain_id: u64,
}

/// Location of the built batch-solvency ELF, relative to this crate.
///
/// Loaded at runtime (like the V2 provers) so the agent builds without the
/// SP1 toolchain and without a prebuilt ELF in the checkout.
pub const BATCH_ELF_RELATIVE_PATH: &str =
    "../../../program/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-pof-program";

/// Absolute path to the batch ELF for this checkout.
pub fn batch_elf_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BATCH_ELF_RELATIVE_PATH)
}

/// Load the batch ELF from disk.
fn load_batch_elf() -> Result<Vec<u8>> {
    let path = batch_elf_path();
    std::fs::read(&path).with_context(|| {
        format!(
            "Batch ELF not found at {} — build it with `cd program && cargo prove build`",
            path.display()
        )
    })
}

/// Build an SP1Stdin from batch proof inputs.
///
/// Writes global inputs followed by per-member inputs in the exact order
/// the SP1 program reads them via `sp1_zkvm::io::read()`.
fn build_sp1_stdin(inputs: &BatchProofInputs) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();

    // Global inputs (order must match program/src/main.rs)
    stdin.write(&inputs.state_root);
    stdin.write(&inputs.policy_id);
    stdin.write(&inputs.epoch);
    stdin.write(&inputs.threshold_wei);
    stdin.write(&inputs.block_number);
    stdin.write(&inputs.chain_id);
    stdin.write(&(inputs.members.len() as u32));

    // Per-member inputs
    for member in &inputs.members {
        stdin.write(&member.member_id);
        stdin.write(&member.watch_target);
        stdin.write(&member.proof_nodes);
    }

    stdin
}

/// Read SP1 public values (bincode) and re-encode as ABI for the Solidity contract.
///
/// The SP1 program commits in this order:
///   state_root (bytes32), policy_id (bytes32), epoch (u64), solvency_root (bytes32),
///   threshold_wei (u64), member_count (u32), block_number (u64), chain_id (u64)
///
/// The Solidity contract decodes:
///   abi.decode(publicValues, (bytes32, bytes32, uint64, bytes32, uint64, uint32, uint64, uint64))
fn decode_and_abi_encode_public_values(
    public_values: &mut sp1_sdk::SP1PublicValues,
) -> Result<ZkProofResult> {
    // Read committed values in the same order as sp1_zkvm::io::commit() in main.rs
    let state_root: [u8; 32] = public_values.read();
    let policy_id: [u8; 32] = public_values.read();
    let epoch: u64 = public_values.read();
    let solvency_root: [u8; 32] = public_values.read();
    let threshold_wei: u64 = public_values.read();
    let member_count: u32 = public_values.read();
    let block_number: u64 = public_values.read();
    let chain_id: u64 = public_values.read();

    // ABI-encode for Solidity: (bytes32, bytes32, uint64, bytes32, uint64, uint32, uint64, uint64)
    // Use alloy's SolValue encoding which produces standard ABI encoding
    let abi_encoded = (
        FixedBytes::<32>::from(state_root),
        FixedBytes::<32>::from(policy_id),
        epoch,
        FixedBytes::<32>::from(solvency_root),
        threshold_wei,
        member_count,
        block_number,
        chain_id,
    ).abi_encode();

    Ok(ZkProofResult {
        proof_bytes: vec![], // Filled by caller for prove() mode
        public_values_abi: abi_encoded,
        solvency_root,
        state_root,
        policy_id,
        epoch,
        threshold_wei,
        member_count,
        block_number,
        chain_id,
    })
}

/// Execute the SP1 program without generating a proof (fast, for testing).
///
/// Runs the RISC-V program in the SP1 executor, verifying all assertions
/// (MPT proofs, hash chains, etc.) but without the expensive proving step.
/// Returns the public values and solvency root.
pub fn execute_sp1_program(inputs: &BatchProofInputs) -> Result<ZkProofResult> {
    let client = ProverClient::builder().cpu().build();
    let elf = Elf::Static(Box::leak(load_batch_elf()?.into_boxed_slice()));
    let stdin = build_sp1_stdin(inputs);

    info!(
        members = inputs.members.len(),
        epoch = inputs.epoch,
        "Executing SP1 program (no proof)"
    );

    let (mut public_values, report) = client
        .execute(elf, stdin)
        .run()
        .context("SP1 program execution failed")?;

    info!(
        total_cycles = report.total_instruction_count(),
        "SP1 execution complete"
    );

    decode_and_abi_encode_public_values(&mut public_values)
}

/// Generate a full SP1 Groth16 proof for on-chain verification.
///
/// This is the production path: runs the prover to generate a STARK proof,
/// recursively compresses it, then wraps it in a Groth16 proof suitable
/// for on-chain verification via ISP1Verifier.
///
/// **Warning**: This is computationally expensive (minutes to hours depending
/// on batch size and hardware). Use `execute_sp1_program()` for testing.
pub fn generate_sp1_proof(inputs: &BatchProofInputs) -> Result<ZkProofResult> {
    let client = ProverClient::builder().cpu().build();
    let elf = Elf::Static(Box::leak(load_batch_elf()?.into_boxed_slice()));
    let stdin = build_sp1_stdin(inputs);
    let pk = client.setup(elf)
        .context("SP1 setup (key generation) failed")?;

    info!(
        members = inputs.members.len(),
        epoch = inputs.epoch,
        "Generating SP1 Groth16 proof (this will take a while)"
    );

    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .context("SP1 proof generation failed")?;

    let proof_bytes = proof.bytes();

    info!(
        proof_size = proof_bytes.len(),
        "SP1 Groth16 proof generated"
    );

    let mut public_values = proof.public_values;
    let mut result = decode_and_abi_encode_public_values(&mut public_values)?;
    result.proof_bytes = proof_bytes;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;

    #[tokio::test]
    async fn test_sign_trusted_assertion() {
        // Generate a random signer for testing
        let signer = PrivateKeySigner::random();
        let key_hex = hex::encode(signer.credential().to_bytes());

        let worker = ProofWorker::new(
            &key_hex,
            1, // mainnet chain ID
            "0x0000000000000000000000000000000000000001",
        ).unwrap();

        let policy_id = [0x01; 32];
        let root = [0xAB; 32];

        let result = worker.sign_trusted_assertion(
            &policy_id,
            &root,
            42,       // epoch
            19_000_000, // block_number
            100,      // member_count
        ).await.unwrap();

        // Signature should be 65 bytes (r + s + v)
        assert_eq!(result.signature.len(), 65);

        // Signer should match the operator
        assert_eq!(result.signer, {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(signer.address().as_slice());
            addr
        });
    }

    #[tokio::test]
    async fn test_sign_different_epochs_produce_different_sigs() {
        let signer = PrivateKeySigner::random();
        let key_hex = hex::encode(signer.credential().to_bytes());

        let worker = ProofWorker::new(
            &key_hex,
            1,
            "0x0000000000000000000000000000000000000001",
        ).unwrap();

        let policy_id = [0x01; 32];
        let root = [0xAB; 32];

        let sig1 = worker.sign_trusted_assertion(&policy_id, &root, 1, 19_000_000, 10)
            .await.unwrap();
        let sig2 = worker.sign_trusted_assertion(&policy_id, &root, 2, 19_000_100, 10)
            .await.unwrap();

        // Different epochs should produce different signatures
        assert_ne!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_invalid_private_key() {
        let result = ProofWorker::new(
            "not_a_valid_key",
            1,
            "0x0000000000000000000000000000000000000001",
        );
        assert!(result.is_err());
    }
}
