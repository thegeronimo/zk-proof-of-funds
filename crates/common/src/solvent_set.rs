//! Solvent-set tree — a Merkle commitment to *every* address meeting a
//! policy threshold at a reference block.
//!
//! This is public data: anyone can derive the set from chain state. Committing
//! to it lets a user prove "I control some address in the set" client-side
//! without revealing which one — the agent never learns member addresses and
//! there is no enrollment (see PRIVACY_V2.md §4).
//!
//! ## Canonical construction
//!
//! ```text
//! addresses sorted ascending (byte order), deduplicated
//! leaf_i = SHA256("zkpof-solvent-leaf-v1" || addr_i)
//! root   = SHA256 binary Merkle root (odd levels duplicate the last node,
//!          identical to crates/common/src/merkle.rs and MerkleVerifier.sol)
//! ```
//!
//! The domain tag separates these leaves from the V1 solvency-tree leaves.

use crate::merkle;
use sha2::{Digest, Sha256};

/// Domain separation tag for solvent-set leaves.
pub const SOLVENT_LEAF_DOMAIN: &[u8] = b"zkpof-solvent-leaf-v1";

/// Compute a solvent-set leaf: `SHA256(domain || address)`.
pub fn compute_solvent_leaf(address: &[u8; 20]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SOLVENT_LEAF_DOMAIN);
    hasher.update(address);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Verify a membership path against a solvent-set root.
pub fn verify_solvent_membership(
    address: &[u8; 20],
    leaf_index: usize,
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    let leaf = compute_solvent_leaf(address);
    merkle::verify_proof(&leaf, leaf_index, siblings, root)
}

/// A canonical solvent set: sorted, deduplicated addresses plus their leaves.
#[derive(Debug, Clone)]
pub struct SolventSet {
    addresses: Vec<[u8; 20]>,
    leaves: Vec<[u8; 32]>,
}

impl SolventSet {
    /// Build a canonical set from an arbitrary address list (sorts + dedups).
    pub fn new(mut addresses: Vec<[u8; 20]>) -> Self {
        addresses.sort_unstable();
        addresses.dedup();
        let leaves = addresses.iter().map(compute_solvent_leaf).collect();
        Self { addresses, leaves }
    }

    /// The canonical (sorted, deduped) address list.
    pub fn addresses(&self) -> &[[u8; 20]] {
        &self.addresses
    }

    /// Number of addresses in the set.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// The Merkle root over the set (zero root for an empty set).
    pub fn root(&self) -> [u8; 32] {
        merkle::compute_root(&self.leaves)
    }

    /// Binary-search the canonical position of an address.
    pub fn index_of(&self, address: &[u8; 20]) -> Option<usize> {
        self.addresses.binary_search(address).ok()
    }

    /// Compute the membership path for an address: `(leaf_index, siblings)`.
    ///
    /// This is a *client-side* operation — the agent must never be asked for a
    /// specific address's path, as the query itself would reveal the address.
    pub fn path_for(&self, address: &[u8; 20]) -> Option<(usize, Vec<[u8; 32]>)> {
        let index = self.index_of(address)?;
        Some((index, merkle::compute_proof(&self.leaves, index)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> [u8; 20] {
        [n; 20]
    }

    #[test]
    fn test_canonicalization_sorts_and_dedups() {
        let set = SolventSet::new(vec![addr(3), addr(1), addr(2), addr(1)]);
        assert_eq!(set.len(), 3);
        assert_eq!(set.addresses(), &[addr(1), addr(2), addr(3)]);
    }

    #[test]
    fn test_root_independent_of_input_order() {
        let a = SolventSet::new(vec![addr(1), addr(2), addr(3)]);
        let b = SolventSet::new(vec![addr(3), addr(1), addr(2)]);
        assert_eq!(a.root(), b.root(), "Canonical root must not depend on input order");
    }

    #[test]
    fn test_empty_set_zero_root() {
        assert_eq!(SolventSet::new(vec![]).root(), [0u8; 32]);
    }

    #[test]
    fn test_membership_paths_verify() {
        let addrs: Vec<[u8; 20]> = (1..=7u8).map(addr).collect();
        let set = SolventSet::new(addrs.clone());
        let root = set.root();

        for a in &addrs {
            let (index, siblings) = set.path_for(a).expect("address is in the set");
            assert!(
                verify_solvent_membership(a, index, &siblings, &root),
                "Path must verify for {:02x?}",
                a[0]
            );
        }
    }

    #[test]
    fn test_non_member_has_no_path_and_fails_verification() {
        let set = SolventSet::new(vec![addr(1), addr(2), addr(3)]);
        let root = set.root();
        assert!(set.path_for(&addr(9)).is_none());

        // A stolen path for a different address must not verify.
        let (index, siblings) = set.path_for(&addr(1)).unwrap();
        assert!(!verify_solvent_membership(&addr(9), index, &siblings, &root));
    }

    #[test]
    fn test_leaf_domain_separation() {
        // A solvent leaf must differ from a bare SHA256 of the address.
        let a = addr(5);
        let mut hasher = Sha256::new();
        hasher.update(a);
        let bare: [u8; 32] = hasher.finalize().into();
        assert_ne!(compute_solvent_leaf(&a), bare);
    }
}
