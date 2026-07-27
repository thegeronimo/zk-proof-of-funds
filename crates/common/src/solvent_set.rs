//! Solvent-set tree — a Merkle commitment to *every* address meeting a
//! policy threshold at a reference block, with per-address **streaks**.
//!
//! This is public data: anyone can derive the set from chain state. Committing
//! to it lets a user prove "I control some address in the set" client-side
//! without revealing which one — the agent never learns member addresses and
//! there is no enrollment (see PRIVACY_V2.md §4).
//!
//! ## Streaks (Phase 11 — the time dimension)
//!
//! A single balance snapshot is gameable: borrow funds for the sampled block,
//! prove, return them. Each leaf therefore carries a `streak` — the number of
//! consecutive epochs (including the current one) the address has been in the
//! set. Membership proofs assert `streak >= minStreak`, so a policy demanding
//! "solvent for ≥ k epochs" makes rented solvency cost roughly as much as
//! real solvency. Streak continuity across epochs is proven by the derivation
//! program (see `solvent_derivation.rs`).
//!
//! ## Canonical construction
//!
//! ```text
//! entries sorted ascending by address (byte order), deduplicated by address
//! leaf_i = SHA256("zkpof-solvent-leaf-v2" || addr_i || streak_i_be4)
//! root   = SHA256 binary Merkle root (odd levels duplicate the last node,
//!          identical to crates/common/src/merkle.rs and MerkleVerifier.sol)
//! ```

use crate::merkle;
use sha2::{Digest, Sha256};

/// Domain separation tag for solvent-set leaves (v2: streak-aware).
pub const SOLVENT_LEAF_DOMAIN: &[u8] = b"zkpof-solvent-leaf-v2";

/// Domain separation tag for the empty-set sentinel root.
pub const EMPTY_SET_DOMAIN: &[u8] = b"zkpof-empty-solvent-set-v1";

/// Root of an empty solvent set: `SHA256("zkpof-empty-solvent-set-v1")`.
///
/// A distinct nonzero value so "nobody qualified this epoch" is publishable
/// and provable, while `bytes32(0)` stays reserved for "no root at all".
/// SHA-256 is not const-evaluable, so this literal is checked against
/// [`empty_set_root`] by `test_empty_set_root_matches_domain`.
pub const EMPTY_SET_ROOT: [u8; 32] = [
    0xd8, 0xbf, 0x5d, 0x04, 0xd1, 0x44, 0xb2, 0xf5, 0x16, 0xe9, 0xe3, 0x85, 0x27, 0x29, 0x48,
    0xb5, 0x4f, 0x53, 0x48, 0x76, 0x04, 0x72, 0x51, 0xf8, 0x7a, 0x3a, 0xaa, 0x17, 0x1b, 0x83,
    0x78, 0x4d,
];

/// Compute the empty-set sentinel root from its domain tag.
pub fn empty_set_root() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EMPTY_SET_DOMAIN);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// One address in the solvent set with its consecutive-epoch streak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolventEntry {
    /// The qualifying address.
    pub address: [u8; 20],
    /// Consecutive epochs in the set, including this one (>= 1).
    pub streak: u32,
}

/// Compute a solvent-set leaf: `SHA256(domain || address || streak_be)`.
pub fn compute_solvent_leaf(address: &[u8; 20], streak: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SOLVENT_LEAF_DOMAIN);
    hasher.update(address);
    hasher.update(streak.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Verify a membership path against a solvent-set root.
pub fn verify_solvent_membership(
    address: &[u8; 20],
    streak: u32,
    leaf_index: usize,
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    let leaf = compute_solvent_leaf(address, streak);
    merkle::verify_proof(&leaf, leaf_index, siblings, root)
}

/// A canonical solvent set: entries sorted by address, deduplicated, plus
/// their leaves.
#[derive(Debug, Clone)]
pub struct SolventSet {
    entries: Vec<SolventEntry>,
    leaves: Vec<[u8; 32]>,
}

impl SolventSet {
    /// Build a canonical set from arbitrary entries (sorts by address and
    /// deduplicates by address, keeping the first occurrence).
    pub fn from_entries(mut entries: Vec<SolventEntry>) -> Self {
        entries.sort_by(|a, b| a.address.cmp(&b.address));
        entries.dedup_by(|a, b| a.address == b.address);
        let leaves = entries
            .iter()
            .map(|e| compute_solvent_leaf(&e.address, e.streak))
            .collect();
        Self { entries, leaves }
    }

    /// Convenience: build a first-epoch set (every address at streak 1).
    pub fn new(addresses: Vec<[u8; 20]>) -> Self {
        Self::from_entries(
            addresses
                .into_iter()
                .map(|address| SolventEntry { address, streak: 1 })
                .collect(),
        )
    }

    /// The canonical (sorted, deduped) entries.
    pub fn entries(&self) -> &[SolventEntry] {
        &self.entries
    }

    /// The canonical address list (allocates).
    pub fn addresses(&self) -> Vec<[u8; 20]> {
        self.entries.iter().map(|e| e.address).collect()
    }

    /// Number of entries in the set.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The Merkle root over the set.
    ///
    /// An empty set hashes to [`EMPTY_SET_ROOT`], not zero: both publication
    /// paths reject a zero root as malformed, so a legitimate epoch in which
    /// nobody qualified was previously unpublishable (review §4.5). The
    /// sentinel is domain-separated, so it can never collide with a real
    /// single-leaf root.
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return EMPTY_SET_ROOT;
        }
        merkle::compute_root(&self.leaves)
    }

    /// Binary-search the canonical position of an address.
    pub fn index_of(&self, address: &[u8; 20]) -> Option<usize> {
        self.entries
            .binary_search_by(|e| e.address.cmp(address))
            .ok()
    }

    /// Look up an address's entry: `(leaf_index, entry)`.
    pub fn entry_for(&self, address: &[u8; 20]) -> Option<(usize, SolventEntry)> {
        let index = self.index_of(address)?;
        Some((index, self.entries[index]))
    }

    /// Compute the membership path for an address:
    /// `(leaf_index, streak, siblings)`.
    ///
    /// This is a *client-side* operation — the agent must never be asked for a
    /// specific address's path, as the query itself would reveal the address.
    pub fn path_for(&self, address: &[u8; 20]) -> Option<(usize, u32, Vec<[u8; 32]>)> {
        let index = self.index_of(address)?;
        Some((
            index,
            self.entries[index].streak,
            merkle::compute_proof(&self.leaves, index),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> [u8; 20] {
        [n; 20]
    }

    fn entry(n: u8, streak: u32) -> SolventEntry {
        SolventEntry { address: addr(n), streak }
    }

    #[test]
    fn test_canonicalization_sorts_and_dedups() {
        let set = SolventSet::from_entries(vec![entry(3, 1), entry(1, 5), entry(2, 2), entry(1, 9)]);
        assert_eq!(set.len(), 3);
        assert_eq!(
            set.entries(),
            &[entry(1, 5), entry(2, 2), entry(3, 1)],
            "Sorted by address, first occurrence kept on dedup"
        );
    }

    #[test]
    fn test_root_independent_of_input_order() {
        let a = SolventSet::from_entries(vec![entry(1, 4), entry(2, 1), entry(3, 2)]);
        let b = SolventSet::from_entries(vec![entry(3, 2), entry(1, 4), entry(2, 1)]);
        assert_eq!(a.root(), b.root(), "Canonical root must not depend on input order");
    }

    #[test]
    fn test_streak_changes_leaf_and_root() {
        let a = SolventSet::from_entries(vec![entry(1, 1), entry(2, 1)]);
        let b = SolventSet::from_entries(vec![entry(1, 2), entry(2, 1)]);
        assert_ne!(
            a.root(),
            b.root(),
            "A different streak must produce a different committed set"
        );
        assert_ne!(
            compute_solvent_leaf(&addr(1), 1),
            compute_solvent_leaf(&addr(1), 2)
        );
    }

    #[test]
    fn test_empty_set_uses_sentinel_root() {
        // "Nobody qualified" must be publishable: the publication paths reject
        // a zero root, so an empty set gets a domain-separated sentinel.
        let root = SolventSet::new(vec![]).root();
        assert_eq!(root, EMPTY_SET_ROOT);
        assert_ne!(root, [0u8; 32], "zero stays reserved for 'no root at all'");
    }

    #[test]
    fn test_empty_set_root_matches_domain() {
        assert_eq!(
            EMPTY_SET_ROOT,
            empty_set_root(),
            "the hardcoded sentinel must equal SHA256(EMPTY_SET_DOMAIN)"
        );
    }

    #[test]
    fn test_empty_sentinel_cannot_collide_with_a_real_set() {
        // A one-entry set's root is its leaf, which is domain-separated
        // differently, so no real set can produce the sentinel.
        let single = SolventSet::new(vec![addr(1)]).root();
        assert_ne!(single, EMPTY_SET_ROOT);
    }

    #[test]
    fn test_new_defaults_to_streak_one() {
        let set = SolventSet::new(vec![addr(2), addr(1)]);
        assert_eq!(set.entries(), &[entry(1, 1), entry(2, 1)]);
    }

    #[test]
    fn test_membership_paths_verify() {
        let entries: Vec<SolventEntry> = (1..=7u8).map(|n| entry(n, n as u32)).collect();
        let set = SolventSet::from_entries(entries.clone());
        let root = set.root();

        for e in &entries {
            let (index, streak, siblings) = set.path_for(&e.address).expect("in set");
            assert_eq!(streak, e.streak);
            assert!(
                verify_solvent_membership(&e.address, streak, index, &siblings, &root),
                "Path must verify for {:02x?}",
                e.address[0]
            );
        }
    }

    #[test]
    fn test_wrong_streak_fails_verification() {
        let set = SolventSet::from_entries(vec![entry(1, 3), entry(2, 1)]);
        let root = set.root();
        let (index, streak, siblings) = set.path_for(&addr(1)).unwrap();
        assert_eq!(streak, 3);
        // Claiming a longer streak than committed must fail.
        assert!(!verify_solvent_membership(&addr(1), 4, index, &siblings, &root));
        assert!(verify_solvent_membership(&addr(1), 3, index, &siblings, &root));
    }

    #[test]
    fn test_non_member_has_no_path_and_fails_verification() {
        let set = SolventSet::new(vec![addr(1), addr(2), addr(3)]);
        let root = set.root();
        assert!(set.path_for(&addr(9)).is_none());

        // A stolen path for a different address must not verify.
        let (index, streak, siblings) = set.path_for(&addr(1)).unwrap();
        assert!(!verify_solvent_membership(&addr(9), streak, index, &siblings, &root));
    }

    #[test]
    fn test_leaf_domain_separation() {
        // A solvent leaf must differ from a bare SHA256 of the address+streak.
        let a = addr(5);
        let mut hasher = Sha256::new();
        hasher.update(a);
        hasher.update(1u32.to_be_bytes());
        let bare: [u8; 32] = hasher.finalize().into();
        assert_ne!(compute_solvent_leaf(&a, 1), bare);
    }
}
