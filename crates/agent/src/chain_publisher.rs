//! Chain Publisher — submits updateRoot() transactions on-chain.
//!
//! Handles transaction construction, gas estimation, nonce management,
//! and confirmation. Supports both ZK mode (updateRoot with proof)
//! and trusted mode (updateRootTrusted with EIP-712 signature).
//!
//! Phase 1 (Trusted Mode): Submits updateRootTrusted() with EIP-712 signature.
//! Phase 4 (ZK Mode): Will also submit updateRoot() with SP1 proof bytes.

use anyhow::{Context, Result};
use tracing::info;

use crate::db::Database;

/// Result of publishing a root on-chain.
#[derive(Debug, Clone)]
pub struct PublishResult {
    /// The epoch that was published.
    pub epoch: u64,
    /// The Merkle root that was published.
    pub root: [u8; 32],
    /// The block at which the root was published (tx inclusion block).
    pub published_at_block: u64,
    /// Whether this was a trusted mode or ZK mode publication.
    pub trusted_mode: bool,
}

/// Chain publisher for submitting root updates on-chain.
///
/// In Phase 1 (trusted mode), this records the epoch in the database.
/// Actual on-chain submission will be implemented in Phase 3/4 when
/// smart contracts are deployed.
pub struct ChainPublisher<'a> {
    db: &'a Database,
}

impl<'a> ChainPublisher<'a> {
    /// Create a new chain publisher.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Record an epoch completion in the database.
    ///
    /// In Phase 1 (trusted mode MVP), we store the epoch record in the database
    /// but don't actually submit an on-chain transaction — contracts aren't
    /// deployed yet. The `published_at_block` field represents the block at
    /// which this would be published once contracts are available.
    ///
    /// In Phase 3+, this will also submit the actual `updateRootTrusted()`
    /// or `updateRoot()` transaction.
    pub fn record_epoch(
        &self,
        policy_id_hex: &str,
        epoch: u64,
        block_number: u64,
        root: &[u8; 32],
        member_count: u32,
        published_at_block: u64,
        proof_bytes: Option<&[u8]>,
    ) -> Result<PublishResult> {
        let root_hex = hex::encode(root);

        self.db.insert_epoch(
            policy_id_hex,
            epoch,
            block_number,
            &root_hex,
            member_count,
            published_at_block,
            proof_bytes,
        ).context("Failed to store epoch record")?;

        info!(
            policy_id = %policy_id_hex,
            epoch = epoch,
            block_number = block_number,
            root = %root_hex,
            member_count = member_count,
            "Epoch recorded"
        );

        Ok(PublishResult {
            epoch,
            root: *root,
            published_at_block,
            trusted_mode: proof_bytes.is_none(),
        })
    }

    // TODO (Phase 3/4): Implement on-chain transaction submission
    // pub async fn submit_trusted_root(
    //     &self,
    //     policy_id: &[u8; 32],
    //     root: &[u8; 32],
    //     epoch: u64,
    //     block_number: u64,
    //     member_count: u32,
    //     signature: &[u8],
    // ) -> Result<PublishResult> { ... }
    //
    // pub async fn submit_zk_root(
    //     &self,
    //     policy_id: &[u8; 32],
    //     root: &[u8; 32],
    //     epoch: u64,
    //     proof_bytes: &[u8],
    //     public_values: &[u8],
    // ) -> Result<PublishResult> { ... }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_epoch() {
        let db = Database::open_in_memory().unwrap();
        let publisher = ChainPublisher::new(&db);

        let root = [0xAB; 32];
        let result = publisher.record_epoch(
            "policy_001",
            1,
            19_000_000,
            &root,
            50,
            19_000_010,
            None,
        ).unwrap();

        assert_eq!(result.epoch, 1);
        assert_eq!(result.root, root);
        assert_eq!(result.published_at_block, 19_000_010);
        assert!(result.trusted_mode);

        // Verify it was stored in the database
        let latest = db.get_latest_epoch("policy_001").unwrap().unwrap();
        assert_eq!(latest.epoch, 1);
        assert_eq!(latest.member_count, 50);
    }

    #[test]
    fn test_record_multiple_epochs() {
        let db = Database::open_in_memory().unwrap();
        let publisher = ChainPublisher::new(&db);

        publisher.record_epoch("policy_001", 1, 19_000_000, &[0xAA; 32], 10, 19_000_010, None).unwrap();
        publisher.record_epoch("policy_001", 2, 19_000_100, &[0xBB; 32], 12, 19_000_110, None).unwrap();
        publisher.record_epoch("policy_001", 3, 19_000_200, &[0xCC; 32], 15, 19_000_210, None).unwrap();

        let latest = db.get_latest_epoch("policy_001").unwrap().unwrap();
        assert_eq!(latest.epoch, 3);
        assert_eq!(latest.member_count, 15);
    }
}
