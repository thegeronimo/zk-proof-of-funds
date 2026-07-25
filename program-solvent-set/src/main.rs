//! ZK Proof of Funds — SP1 Solvent-Set Derivation Program (Stage B)
//!
//! Proves that a solvent set was correctly derived from Ethereum state:
//!
//!   "Every entry in the committed set had a balance >= threshold at the
//!    reference block, proven via EIP-1186 against `state_root`, and every
//!    streak is continuous with the previously published set (recommitted
//!    and exposed as `prev_root`)."
//!
//! This removes the operator *safety* trust from solvent-set publication:
//! `SolventSetOracle.publishRootProven` verifies this proof, binds
//! `state_root` to the chain via the block header, checks `prev_root`
//! against its stored history, and accepts the root from **anyone**.
//! Candidate completeness (censorship) remains operator-side — see
//! PRIVACY_V2.md §4.4.
//!
//! Public values committed as one ABI blob (320 bytes):
//!   abi.encode(bytes32 stateRoot, bytes32 prevRoot, bytes32 newRoot,
//!              bytes32 policyId, uint64 epoch, uint64 blockNumber,
//!              uint64 chainId, uint256 thresholdWei,
//!              uint32 memberCount, uint32 candidateCount)
//!
//! The statement is implemented once, in `zk_pof_common::solvent_derivation`,
//! shared byte-for-byte with the host-side mirror used for input building and
//! testing.
//!
//! Build: cd program-solvent-set && cargo prove build

#![no_main]
sp1_zkvm::entrypoint!(main);

use zk_pof_common::solvent_derivation::{
    execute_derivation_statement, CandidateProof, DerivationWitness, TokenConfig,
};
use zk_pof_common::solvent_set::SolventEntry;

pub fn main() {
    // ── 1. Read public inputs ──────────────────────────────────────────
    let state_root: [u8; 32] = sp1_zkvm::io::read();
    let policy_id: [u8; 32] = sp1_zkvm::io::read();
    let epoch: u64 = sp1_zkvm::io::read();
    let block_number: u64 = sp1_zkvm::io::read();
    let chain_id: u64 = sp1_zkvm::io::read();
    let threshold_wei: u128 = sp1_zkvm::io::read();
    // ERC-20 mode: (token address, balanceOf mapping slot); None = native ETH.
    let token_config: Option<([u8; 20], u64)> = sp1_zkvm::io::read();

    // ── 2. Read the witness ────────────────────────────────────────────
    // Previous set entries as (address, streak) pairs.
    let prev_raw: Vec<([u8; 20], u32)> = sp1_zkvm::io::read();
    // ERC-20 mode: the token contract's account proof (empty for native).
    let token_account_proof: Vec<Vec<u8>> = sp1_zkvm::io::read();
    // Candidates as (address, proof_nodes) pairs.
    let candidate_count: u32 = sp1_zkvm::io::read();
    let mut candidates = Vec::with_capacity(candidate_count as usize);
    for _ in 0..candidate_count {
        let address: [u8; 20] = sp1_zkvm::io::read();
        let proof_nodes: Vec<Vec<u8>> = sp1_zkvm::io::read();
        candidates.push(CandidateProof { address, proof_nodes });
    }

    let witness = DerivationWitness {
        candidates,
        prev_entries: prev_raw
            .into_iter()
            .map(|(address, streak)| SolventEntry { address, streak })
            .collect(),
        token_account_proof,
    };
    let token = token_config.map(|(address, balance_slot)| TokenConfig { address, balance_slot });

    // ── 3. Execute the statement (panics abort the proof) ──────────────
    let public_values = execute_derivation_statement(
        &witness,
        &state_root,
        &policy_id,
        epoch,
        block_number,
        chain_id,
        threshold_wei,
        token.as_ref(),
    )
    .expect("derivation statement not satisfied");

    // ── 4. Commit ABI-encoded public values ────────────────────────────
    sp1_zkvm::io::commit_slice(&public_values.abi_encode());
}
