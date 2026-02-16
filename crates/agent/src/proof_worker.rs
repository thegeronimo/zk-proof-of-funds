//! Proof Workers — generates EIP-712 signatures (trusted mode) or SP1 batch proofs (ZK mode).
//!
//! In trusted mode (Phase 1): signs an EIP-712 typed data assertion with the operator key.
//! In ZK mode (Phase 2): loads the SP1 ELF binary, constructs stdin, generates Groth16 proof.

use anyhow::{Context, Result};
use alloy::primitives::{Address, FixedBytes};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolStruct, eip712_domain};
use alloy::sol;
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

    // TODO (Phase 2.4): Implement SP1 proof generation for ZK mode
    // pub async fn generate_sp1_proof(&self, ...) -> Result<Vec<u8>> { ... }
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
