//! SHA-256 binary Merkle tree implementation.
//!
//! This implementation is shared between the off-chain agent and must match
//! the on-chain MerkleVerifier.sol exactly. The SP1 program also uses the
//! same algorithm (implemented inline to avoid cross-crate zkVM deps).
//!
//! ## Leaf Construction
//!
//! ```text
//! leaf = SHA256(member_id || status || epoch_be_bytes || policy_id)
//! ```
//!
//! ## Tree Construction
//!
//! Standard binary Merkle tree with SHA256 internal nodes.
//! If the number of leaves at any level is odd, the last leaf is duplicated.

use sha2::{Digest, Sha256};

/// Compute a Merkle leaf for the solvency tree.
///
/// ```text
/// leaf = SHA256(member_id || status || epoch.to_be_bytes() || policy_id)
/// ```
pub fn compute_leaf(
    member_id: &[u8; 32],
    status: u8,
    epoch: u64,
    policy_id: &[u8; 32],
) -> [u8; 32] {
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
/// Uses a standard binary Merkle tree. If the number of leaves at any level
/// is odd, the last leaf is duplicated (standard padding).
///
/// Returns a zero hash for an empty tree.
pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
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
                &current_level[i] // Duplicate last node if odd count
            };
            next_level.push(hash_pair(left, right));
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Compute a Merkle inclusion proof for the leaf at `index`.
///
/// Returns the sibling hashes from leaf to root. Each element is a sibling
/// hash; the verifier rebuilds the root using the leaf, the proof, and the
/// index to determine left/right placement at each level.
pub fn compute_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    assert!(index < leaves.len(), "Index out of range");

    let mut proof = Vec::new();
    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        // Pad to even length by duplicating last element
        if current_level.len() % 2 == 1 {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }

        // The sibling is at the paired index
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        proof.push(current_level[sibling_idx]);

        // Build next level
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for i in (0..current_level.len()).step_by(2) {
            next_level.push(hash_pair(&current_level[i], &current_level[i + 1]));
        }

        current_level = next_level;
        idx /= 2;
    }

    proof
}

/// Verify a Merkle inclusion proof.
///
/// Given a leaf, its index, the proof path, and the expected root,
/// returns true if the proof is valid.
pub fn verify_proof(
    leaf: &[u8; 32],
    index: usize,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    let mut current = *leaf;
    let mut idx = index;

    for sibling in proof {
        if idx % 2 == 0 {
            current = hash_pair(&current, sibling);
        } else {
            current = hash_pair(sibling, &current);
        }
        idx /= 2;
    }

    current == *root
}

/// Hash two 32-byte values together: SHA256(left || right)
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let leaf = [0xAA; 32];
        let root = compute_root(&[leaf]);
        assert_eq!(root, leaf, "Single leaf should be its own root");
    }

    #[test]
    fn test_empty_tree() {
        let root = compute_root(&[]);
        assert_eq!(root, [0u8; 32], "Empty tree should have zero root");
    }

    #[test]
    fn test_two_leaves() {
        let leaf_a = [0x01; 32];
        let leaf_b = [0x02; 32];
        let root = compute_root(&[leaf_a, leaf_b]);

        // Manually compute expected root
        let expected = hash_pair(&leaf_a, &leaf_b);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_three_leaves_padding() {
        let leaf_a = [0x01; 32];
        let leaf_b = [0x02; 32];
        let leaf_c = [0x03; 32];
        let root = compute_root(&[leaf_a, leaf_b, leaf_c]);

        // With 3 leaves, leaf_c is duplicated:
        // Level 1: H(a,b), H(c,c)
        // Level 0: H(H(a,b), H(c,c))
        let h_ab = hash_pair(&leaf_a, &leaf_b);
        let h_cc = hash_pair(&leaf_c, &leaf_c);
        let expected = hash_pair(&h_ab, &h_cc);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let root = compute_root(&leaves);

        let h_01 = hash_pair(&leaves[0], &leaves[1]);
        let h_23 = hash_pair(&leaves[2], &leaves[3]);
        let expected = hash_pair(&h_01, &h_23);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_proof_verification_two_leaves() {
        let leaf_a = [0x01; 32];
        let leaf_b = [0x02; 32];
        let leaves = [leaf_a, leaf_b];
        let root = compute_root(&leaves);

        // Proof for leaf 0
        let proof_0 = compute_proof(&leaves, 0);
        assert!(verify_proof(&leaf_a, 0, &proof_0, &root));

        // Proof for leaf 1
        let proof_1 = compute_proof(&leaves, 1);
        assert!(verify_proof(&leaf_b, 1, &proof_1, &root));
    }

    #[test]
    fn test_proof_verification_four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let root = compute_root(&leaves);

        for i in 0..4 {
            let proof = compute_proof(&leaves, i);
            assert!(
                verify_proof(&leaves[i], i, &proof, &root),
                "Proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_verification_seven_leaves() {
        let leaves: Vec<[u8; 32]> = (0..7u8).map(|i| [i + 10; 32]).collect();
        let root = compute_root(&leaves);

        for i in 0..7 {
            let proof = compute_proof(&leaves, i);
            assert!(
                verify_proof(&leaves[i], i, &proof, &root),
                "Proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_invalid_proof_rejected() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let root = compute_root(&leaves);

        // Try to verify leaf 0 with proof for leaf 1 — should fail
        let proof_1 = compute_proof(&leaves, 1);
        assert!(!verify_proof(&leaves[0], 0, &proof_1, &root));
    }

    #[test]
    fn test_compute_leaf_deterministic() {
        let member_id = [0xAA; 32];
        let policy_id = [0xBB; 32];

        let leaf1 = compute_leaf(&member_id, 1, 42, &policy_id);
        let leaf2 = compute_leaf(&member_id, 1, 42, &policy_id);
        assert_eq!(leaf1, leaf2, "Leaf computation should be deterministic");

        // Different status should produce different leaf
        let leaf3 = compute_leaf(&member_id, 0, 42, &policy_id);
        assert_ne!(leaf1, leaf3, "Different status should produce different leaf");

        // Different epoch should produce different leaf
        let leaf4 = compute_leaf(&member_id, 1, 43, &policy_id);
        assert_ne!(leaf1, leaf4, "Different epoch should produce different leaf");
    }
}
