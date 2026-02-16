//! Merkle Proof Service — stores Merkle trees and serves per-member proofs.
//!
//! After each epoch, the complete Merkle tree is stored so that individual
//! membership proofs can be served on demand. The tree is a binary SHA-256
//! Merkle tree where each leaf = SHA256(memberId || status || epoch || policyId).
//!
//! Core Merkle algorithms (compute_root, compute_proof, verify_proof) are in
//! `zk_pof_common::merkle`. This module wraps them with database storage and
//! higher-level operations.

use anyhow::{bail, Context, Result};
use tracing::{debug, info};

use zk_pof_common::merkle;
use crate::db::Database;

/// The Merkle proof service, responsible for building trees, storing them,
/// and serving per-member inclusion proofs.
pub struct MerkleService<'a> {
    db: &'a Database,
}

/// Input for building a Merkle tree leaf.
#[derive(Debug, Clone)]
pub struct LeafInput {
    pub member_id: [u8; 32],
    pub status: u8,            // 1 = solvent, 0 = insolvent
    pub member_id_hex: String, // for DB lookups
}

/// Result of building an epoch's Merkle tree.
#[derive(Debug, Clone)]
pub struct EpochTreeResult {
    /// The computed Merkle root.
    pub root: [u8; 32],
    /// Number of leaves (members) in the tree.
    pub member_count: u32,
    /// Ordered list of leaf hashes (for later proof generation).
    pub leaves: Vec<[u8; 32]>,
    /// Mapping: leaf index -> member_id_hex (for resolving proofs).
    pub member_indices: Vec<(usize, String)>,
}

/// A per-member Merkle proof ready for API serving.
#[derive(Debug, Clone)]
pub struct MemberProof {
    pub member_id: [u8; 32],
    pub status: u8,
    pub epoch: u64,
    pub leaf_index: u32,
    pub merkle_proof: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

impl<'a> MerkleService<'a> {
    /// Create a new Merkle service.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Build the Merkle tree for an epoch.
    ///
    /// Takes a list of members with their current solvency status,
    /// computes the leaves, builds the tree, stores it in the database,
    /// and returns the root + metadata.
    pub fn build_epoch_tree(
        &self,
        policy_id: &[u8; 32],
        epoch: u64,
        leaf_inputs: &[LeafInput],
        policy_id_hex: &str,
    ) -> Result<EpochTreeResult> {
        if leaf_inputs.is_empty() {
            bail!("Cannot build Merkle tree with no members");
        }

        // 1. Compute all leaves
        let mut leaves = Vec::with_capacity(leaf_inputs.len());
        let mut member_indices = Vec::with_capacity(leaf_inputs.len());

        for (i, input) in leaf_inputs.iter().enumerate() {
            let leaf = merkle::compute_leaf(
                &input.member_id,
                input.status,
                epoch,
                policy_id,
            );
            leaves.push(leaf);
            member_indices.push((i, input.member_id_hex.clone()));
        }

        // 2. Compute the Merkle root
        let root = merkle::compute_root(&leaves);

        info!(
            policy_id = %policy_id_hex,
            epoch = epoch,
            member_count = leaves.len(),
            root = %hex::encode(root),
            "Built Merkle tree for epoch"
        );

        // 3. Store the tree in the database (leaves as JSON hex strings)
        let leaves_json = serde_json::to_string(
            &leaves.iter().map(hex::encode).collect::<Vec<_>>()
        ).context("Failed to serialize leaves")?;

        self.db.store_merkle_tree(policy_id_hex, epoch, &leaves_json)?;

        Ok(EpochTreeResult {
            root,
            member_count: leaves.len() as u32,
            leaves,
            member_indices,
        })
    }

    /// Generate a Merkle proof for a specific member in a given epoch.
    ///
    /// Looks up the stored tree, finds the member's leaf index, and computes
    /// the inclusion proof.
    pub fn get_member_proof(
        &self,
        policy_id_hex: &str,
        epoch: u64,
        member_id_hex: &str,
        member_id: &[u8; 32],
        status: u8,
        policy_id: &[u8; 32],
    ) -> Result<MemberProof> {
        // 1. Retrieve stored tree from database
        let leaves_json = self.db.get_merkle_tree(policy_id_hex, epoch)?
            .context("No Merkle tree found for this epoch")?;

        let leaf_hex_strings: Vec<String> = serde_json::from_str(&leaves_json)
            .context("Failed to deserialize stored leaves")?;

        let leaves: Vec<[u8; 32]> = leaf_hex_strings
            .iter()
            .map(|h| {
                let bytes = hex::decode(h)?;
                if bytes.len() != 32 {
                    bail!("Invalid leaf hash length");
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            })
            .collect::<Result<Vec<_>>>()?;

        // 2. Compute the expected leaf for this member
        let expected_leaf = merkle::compute_leaf(member_id, status, epoch, policy_id);

        // 3. Find the leaf index
        let leaf_index = leaves.iter()
            .position(|l| *l == expected_leaf)
            .context("Member leaf not found in tree — status may have changed")?;

        // 4. Compute the proof
        let proof = merkle::compute_proof(&leaves, leaf_index);
        let root = merkle::compute_root(&leaves);

        debug!(
            member_id = %member_id_hex,
            epoch = epoch,
            leaf_index = leaf_index,
            proof_len = proof.len(),
            "Generated Merkle proof for member"
        );

        Ok(MemberProof {
            member_id: *member_id,
            status,
            epoch,
            leaf_index: leaf_index as u32,
            merkle_proof: proof,
            root,
        })
    }

    /// Verify a Merkle proof locally (for testing / validation).
    pub fn verify_proof(proof: &MemberProof) -> bool {
        let leaf = merkle::compute_leaf(
            &proof.member_id,
            proof.status,
            proof.epoch,
            &[0u8; 32], // caller must supply policy_id if needed
        );
        merkle::verify_proof(
            &leaf,
            proof.leaf_index as usize,
            &proof.merkle_proof,
            &proof.root,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    fn make_member_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn test_build_epoch_tree() {
        let db = Database::open_in_memory().unwrap();
        let svc = MerkleService::new(&db);

        let policy_id = [0x01; 32];
        let policy_id_hex = hex::encode(policy_id);

        let inputs = vec![
            LeafInput {
                member_id: make_member_id(0xAA),
                status: 1,
                member_id_hex: hex::encode(make_member_id(0xAA)),
            },
            LeafInput {
                member_id: make_member_id(0xBB),
                status: 1,
                member_id_hex: hex::encode(make_member_id(0xBB)),
            },
            LeafInput {
                member_id: make_member_id(0xCC),
                status: 0,
                member_id_hex: hex::encode(make_member_id(0xCC)),
            },
        ];

        let result = svc.build_epoch_tree(&policy_id, 1, &inputs, &policy_id_hex).unwrap();

        assert_eq!(result.member_count, 3);
        assert_ne!(result.root, [0u8; 32]);
        assert_eq!(result.leaves.len(), 3);
        assert_eq!(result.member_indices.len(), 3);
    }

    #[test]
    fn test_build_and_retrieve_proof() {
        let db = Database::open_in_memory().unwrap();
        let svc = MerkleService::new(&db);

        let policy_id = [0x01; 32];
        let policy_id_hex = hex::encode(policy_id);

        let inputs = vec![
            LeafInput {
                member_id: make_member_id(0xAA),
                status: 1,
                member_id_hex: hex::encode(make_member_id(0xAA)),
            },
            LeafInput {
                member_id: make_member_id(0xBB),
                status: 1,
                member_id_hex: hex::encode(make_member_id(0xBB)),
            },
        ];

        let tree_result = svc.build_epoch_tree(&policy_id, 42, &inputs, &policy_id_hex).unwrap();

        // Get proof for member 0xAA
        let proof = svc.get_member_proof(
            &policy_id_hex,
            42,
            &hex::encode(make_member_id(0xAA)),
            &make_member_id(0xAA),
            1,
            &policy_id,
        ).unwrap();

        assert_eq!(proof.epoch, 42);
        assert_eq!(proof.status, 1);
        assert_eq!(proof.root, tree_result.root);

        // Verify the proof locally using the merkle module
        let leaf = merkle::compute_leaf(&make_member_id(0xAA), 1, 42, &policy_id);
        assert!(merkle::verify_proof(
            &leaf,
            proof.leaf_index as usize,
            &proof.merkle_proof,
            &proof.root,
        ));
    }

    #[test]
    fn test_empty_tree_rejected() {
        let db = Database::open_in_memory().unwrap();
        let svc = MerkleService::new(&db);

        let result = svc.build_epoch_tree(&[0x01; 32], 1, &[], "01");
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_for_all_members() {
        let db = Database::open_in_memory().unwrap();
        let svc = MerkleService::new(&db);

        let policy_id = [0x01; 32];
        let policy_id_hex = hex::encode(policy_id);

        let inputs: Vec<LeafInput> = (0..7u8).map(|i| LeafInput {
            member_id: make_member_id(i + 10),
            status: if i % 3 == 0 { 0 } else { 1 },
            member_id_hex: hex::encode(make_member_id(i + 10)),
        }).collect();

        let tree_result = svc.build_epoch_tree(&policy_id, 5, &inputs, &policy_id_hex).unwrap();

        // Verify every member can get a valid proof
        for input in &inputs {
            let proof = svc.get_member_proof(
                &policy_id_hex,
                5,
                &input.member_id_hex,
                &input.member_id,
                input.status,
                &policy_id,
            ).unwrap();

            let leaf = merkle::compute_leaf(&input.member_id, input.status, 5, &policy_id);
            assert!(
                merkle::verify_proof(&leaf, proof.leaf_index as usize, &proof.merkle_proof, &proof.root),
                "Proof verification failed for member {}",
                input.member_id_hex
            );
            assert_eq!(proof.root, tree_result.root);
        }
    }
}
