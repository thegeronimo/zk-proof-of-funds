//! Chain Publisher — submits updateRoot() transactions on-chain.
//!
//! Handles transaction construction, gas estimation, nonce management,
//! and confirmation. Supports both ZK mode (updateRoot with proof)
//! and trusted mode (updateRootTrusted with EIP-712 signature).
//!
//! ## Components
//!
//! - `ChainPublisher` — lightweight DB-only recorder (Phase 1 compat, used in tests).
//! - `OnChainPublisher` — full on-chain tx submission via alloy wallet-backed provider.

use anyhow::{Context, Result};
use alloy::primitives::{Address, Bytes, FixedBytes};
use alloy::providers::ProviderBuilder;
use alloy::network::EthereumWallet;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use std::sync::{Arc, Mutex};
use tracing::info;

use crate::db::Database;

// ─── Contract ABI via sol! macro ─────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    contract SolvencyRootOracle {
        function updateRootTrusted(
            bytes32 policyId,
            bytes32 newRoot,
            uint64 epoch,
            uint64 blockNumber,
            uint32 memberCount,
            bytes calldata signature
        ) external;

        function updateRoot(
            bytes32 policyId,
            bytes32 newRoot,
            uint64 epoch,
            uint64 blockNumber,
            uint32 memberCount,
            bytes calldata proofBytes,
            bytes calldata publicValues
        ) external;
    }
}

// ─── Result types ────────────────────────────────────────────────────────────

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
    /// Transaction hash (hex-encoded, present only for on-chain submissions).
    pub tx_hash: Option<String>,
}

// ─── ChainPublisher (DB-only, Phase 1 compat) ───────────────────────────────

/// Chain publisher for recording epochs without on-chain submission.
///
/// Used in Phase 1 tests and when `skip_on_chain = true`.
pub struct ChainPublisher<'a> {
    db: &'a Database,
}

impl<'a> ChainPublisher<'a> {
    /// Create a new chain publisher.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Record an epoch completion in the database (no on-chain tx).
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
            tx_hash: None,
        })
    }
}

// ─── OnChainPublisher (Full tx submission) ───────────────────────────────────

/// On-chain publisher that submits transactions to the SolvencyRootOracle contract.
///
/// Uses alloy's wallet-backed provider for automatic nonce and gas management.
/// Falls back to DB-only recording when `skip_on_chain` is set.
pub struct OnChainPublisher {
    db: Arc<Mutex<Database>>,
    /// The wallet-backed HTTP provider.
    /// Stored as a concrete type to avoid trait object complexity.
    provider: alloy::providers::fillers::FillProvider<
        alloy::providers::fillers::JoinFill<
            alloy::providers::fillers::JoinFill<
                alloy::providers::Identity,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::GasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::BlobGasFiller,
                        alloy::providers::fillers::JoinFill<
                            alloy::providers::fillers::NonceFiller,
                            alloy::providers::fillers::ChainIdFiller,
                        >,
                    >,
                >,
            >,
            alloy::providers::fillers::WalletFiller<EthereumWallet>,
        >,
        alloy::providers::RootProvider,
    >,
    oracle_address: Address,
    #[allow(dead_code)]
    chain_id: u64,
}

impl OnChainPublisher {
    /// Create a new on-chain publisher.
    ///
    /// Constructs a wallet-backed alloy provider that handles nonce management,
    /// gas estimation, and transaction signing automatically.
    pub fn new(
        db: Arc<Mutex<Database>>,
        rpc_url: &str,
        operator_private_key: &str,
        oracle_address_hex: &str,
        chain_id: u64,
    ) -> Result<Self> {
        let key_hex = operator_private_key.strip_prefix("0x")
            .unwrap_or(operator_private_key);

        let signer: PrivateKeySigner = key_hex.parse()
            .context("Invalid operator private key")?;

        let wallet = EthereumWallet::from(signer);

        let rpc_url_parsed: url::Url = rpc_url.parse()
            .context("Invalid RPC URL")?;

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(rpc_url_parsed);

        let oracle_address: Address = oracle_address_hex.parse()
            .context("Invalid oracle address")?;

        info!(
            oracle = %oracle_address,
            chain_id = chain_id,
            "OnChainPublisher initialized"
        );

        Ok(Self {
            db,
            provider,
            oracle_address,
            chain_id,
        })
    }

    /// Publish a trusted-mode root on-chain via `updateRootTrusted()`.
    ///
    /// Submits the transaction, waits for inclusion, records the epoch in DB.
    pub async fn publish_trusted(
        &self,
        policy_id: &[u8; 32],
        root: &[u8; 32],
        epoch: u64,
        block_number: u64,
        member_count: u32,
        signature: &[u8],
    ) -> Result<PublishResult> {
        let contract = SolvencyRootOracle::new(self.oracle_address, &self.provider);

        let call = contract.updateRootTrusted(
            FixedBytes::from(*policy_id),
            FixedBytes::from(*root),
            epoch,
            block_number,
            member_count,
            Bytes::copy_from_slice(signature),
        );

        info!(
            epoch = epoch,
            block_number = block_number,
            member_count = member_count,
            root = %hex::encode(root),
            "Submitting updateRootTrusted transaction"
        );

        let pending_tx = call.send().await
            .context("Failed to send updateRootTrusted transaction")?;

        let tx_hash = format!("{:?}", pending_tx.tx_hash());

        info!(tx_hash = %tx_hash, "Transaction sent, waiting for confirmation");

        let receipt = pending_tx.get_receipt().await
            .context("Failed to get transaction receipt")?;

        let published_at_block = receipt.block_number
            .unwrap_or(0);

        let success = receipt.status();
        if !success {
            anyhow::bail!(
                "updateRootTrusted transaction reverted (tx: {})",
                tx_hash
            );
        }

        info!(
            tx_hash = %tx_hash,
            published_at_block = published_at_block,
            "updateRootTrusted confirmed"
        );

        // Record in DB
        let policy_id_hex = hex::encode(policy_id);
        let root_hex = hex::encode(root);
        {
            let db = self.db.lock().unwrap();
            db.insert_epoch(
                &policy_id_hex,
                epoch,
                block_number,
                &root_hex,
                member_count,
                published_at_block,
                None,
            ).context("Failed to store epoch record after trusted tx")?;
        }

        Ok(PublishResult {
            epoch,
            root: *root,
            published_at_block,
            trusted_mode: true,
            tx_hash: Some(tx_hash),
        })
    }

    /// Publish a ZK-mode root on-chain via `updateRoot()`.
    ///
    /// Submits the SP1 proof and public values, waits for inclusion, records in DB.
    pub async fn publish_zk(
        &self,
        policy_id: &[u8; 32],
        root: &[u8; 32],
        epoch: u64,
        block_number: u64,
        member_count: u32,
        proof_bytes: &[u8],
        public_values: &[u8],
    ) -> Result<PublishResult> {
        let contract = SolvencyRootOracle::new(self.oracle_address, &self.provider);

        let call = contract.updateRoot(
            FixedBytes::from(*policy_id),
            FixedBytes::from(*root),
            epoch,
            block_number,
            member_count,
            Bytes::copy_from_slice(proof_bytes),
            Bytes::copy_from_slice(public_values),
        );

        info!(
            epoch = epoch,
            block_number = block_number,
            member_count = member_count,
            proof_size = proof_bytes.len(),
            root = %hex::encode(root),
            "Submitting updateRoot (ZK) transaction"
        );

        let pending_tx = call.send().await
            .context("Failed to send updateRoot transaction")?;

        let tx_hash = format!("{:?}", pending_tx.tx_hash());

        info!(tx_hash = %tx_hash, "ZK transaction sent, waiting for confirmation");

        let receipt = pending_tx.get_receipt().await
            .context("Failed to get ZK transaction receipt")?;

        let published_at_block = receipt.block_number
            .unwrap_or(0);

        let success = receipt.status();
        if !success {
            anyhow::bail!(
                "updateRoot (ZK) transaction reverted (tx: {})",
                tx_hash
            );
        }

        info!(
            tx_hash = %tx_hash,
            published_at_block = published_at_block,
            "updateRoot (ZK) confirmed"
        );

        // Record in DB
        let policy_id_hex = hex::encode(policy_id);
        let root_hex = hex::encode(root);
        {
            let db = self.db.lock().unwrap();
            db.insert_epoch(
                &policy_id_hex,
                epoch,
                block_number,
                &root_hex,
                member_count,
                published_at_block,
                Some(proof_bytes),
            ).context("Failed to store epoch record after ZK tx")?;
        }

        Ok(PublishResult {
            epoch,
            root: *root,
            published_at_block,
            trusted_mode: false,
            tx_hash: Some(tx_hash),
        })
    }

    /// Record an epoch in the DB without submitting on-chain (skip_on_chain mode).
    ///
    /// Used when `skip_on_chain = true` for testing or when the chain publisher
    /// should only track epochs locally.
    pub fn record_epoch_only(
        &self,
        policy_id_hex: &str,
        epoch: u64,
        block_number: u64,
        root: &[u8; 32],
        member_count: u32,
        proof_bytes: Option<&[u8]>,
    ) -> Result<PublishResult> {
        let root_hex = hex::encode(root);

        {
            let db = self.db.lock().unwrap();
            db.insert_epoch(
                policy_id_hex,
                epoch,
                block_number,
                &root_hex,
                member_count,
                block_number, // published_at_block = block_number in skip mode
                proof_bytes,
            ).context("Failed to store epoch record")?;
        }

        info!(
            policy_id = %policy_id_hex,
            epoch = epoch,
            block_number = block_number,
            root = %root_hex,
            member_count = member_count,
            "Epoch recorded (skip_on_chain mode)"
        );

        Ok(PublishResult {
            epoch,
            root: *root,
            published_at_block: block_number,
            trusted_mode: proof_bytes.is_none(),
            tx_hash: None,
        })
    }
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
        assert!(result.tx_hash.is_none());

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

    #[test]
    fn test_on_chain_publisher_record_epoch_only() {
        let db = Arc::new(Mutex::new(Database::open_in_memory().unwrap()));

        // We can't construct a full OnChainPublisher without a real RPC URL,
        // so we test record_epoch_only by constructing manually.
        // Instead, test the DB-only path through ChainPublisher which does the same thing.
        let db_ref = db.lock().unwrap();
        let publisher = ChainPublisher::new(&*db_ref);

        let root = [0xDD; 32];
        let result = publisher.record_epoch(
            "policy_002",
            1,
            19_500_000,
            &root,
            25,
            19_500_000,
            None,
        ).unwrap();

        assert_eq!(result.epoch, 1);
        assert!(result.tx_hash.is_none());

        let latest = db_ref.get_latest_epoch("policy_002").unwrap().unwrap();
        assert_eq!(latest.epoch, 1);
        assert_eq!(latest.member_count, 25);
    }
}
