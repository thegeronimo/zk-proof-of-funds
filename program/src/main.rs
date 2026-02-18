//! ZK Proof of Funds — SP1 Batch Solvency Root Updater
//!
//! This program runs inside SP1's RISC-V zkVM. It processes a batch of members
//! for a single policy in a single epoch:
//!
//! 1. Reads global inputs (state_root, policy_id, epoch, threshold, etc.)
//! 2. For each member:
//!    a. Reads member inputs (member_id, watch_target, MPT proof nodes)
//!    b. Verifies the EIP-1186 MPT proof against the state root
//!    c. Extracts the balance from the proven account state
//!    d. Determines status (balance >= threshold → 1, else → 0)
//!    e. Computes leaf = SHA256(member_id || status || epoch || policy_id)
//! 3. Builds the Merkle tree from all leaves
//! 4. Commits public outputs (solvency_root, policy_id, epoch, etc.)
//!
//! Build: cd program && cargo prove build
//! The output ELF binary is used by the host (crates/agent) to generate proofs.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

/// Main entry point for the SP1 batch solvency root updater.
///
/// Processes a batch of members for a single policy/epoch:
/// verifies each member's balance via MPT proof, determines solvency status,
/// and commits the resulting Merkle root as a public output.
pub fn main() {
    // ── 1. Read global inputs ──────────────────────────────────────────
    let state_root: [u8; 32] = sp1_zkvm::io::read();
    let policy_id: [u8; 32] = sp1_zkvm::io::read();
    let epoch: u64 = sp1_zkvm::io::read();
    let threshold_wei: u64 = sp1_zkvm::io::read();
    let block_number: u64 = sp1_zkvm::io::read();
    let chain_id: u64 = sp1_zkvm::io::read();
    let member_count: u32 = sp1_zkvm::io::read();

    // ── 2. Process each member ─────────────────────────────────────────
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(member_count as usize);

    for _ in 0..member_count {
        let member_id: [u8; 32] = sp1_zkvm::io::read();
        let watch_target: [u8; 20] = sp1_zkvm::io::read();
        let proof_nodes: Vec<Vec<u8>> = sp1_zkvm::io::read();

        // Verify the EIP-1186 MPT proof against the state root and extract balance.
        // Panics (aborting the proof) if the proof is invalid.
        let balance_bytes = mpt::verify_account_balance(
            &state_root, &watch_target, &proof_nodes,
        );

        // 2b. Determine status: compare balance >= threshold (both as big-endian U256)
        let mut threshold_bytes = [0u8; 32];
        threshold_bytes[24..].copy_from_slice(&threshold_wei.to_be_bytes());
        let status: u8 = if balance_bytes >= threshold_bytes { 1 } else { 0 };

        // 2c. Compute leaf = SHA256(member_id || status || epoch || policy_id)
        let leaf = compute_leaf(&member_id, status, epoch, &policy_id);
        leaves.push(leaf);
    }

    // ── 3. Build Merkle tree and compute root ──────────────────────────
    let solvency_root = compute_merkle_root(&leaves);

    // ── 4. Commit public outputs ───────────────────────────────────────
    sp1_zkvm::io::commit(&state_root);
    sp1_zkvm::io::commit(&policy_id);
    sp1_zkvm::io::commit(&epoch);
    sp1_zkvm::io::commit(&solvency_root);
    sp1_zkvm::io::commit(&threshold_wei);
    sp1_zkvm::io::commit(&member_count);
    sp1_zkvm::io::commit(&block_number);
    sp1_zkvm::io::commit(&chain_id);
}

/// Compute a Merkle leaf: SHA256(member_id || status || epoch_be || policy_id)
fn compute_leaf(member_id: &[u8; 32], status: u8, epoch: u64, policy_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(member_id);
    hasher.update([status]);
    hasher.update(epoch.to_be_bytes());
    hasher.update(policy_id);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute the Merkle root from a list of leaves using SHA-256.
///
/// Uses a simple binary Merkle tree. If the number of leaves at any level
/// is odd, the last leaf is duplicated (standard padding).
fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32]; // Empty tree → zero root
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

        for i in (0..current_level.len()).step_by(2) {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                // Odd number of nodes — duplicate the last one
                &current_level[i]
            };

            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            next_level.push(hash);
        }

        current_level = next_level;
    }

    current_level[0]
}

mod mpt;
