//! Epoch Processor — orchestrates the full epoch update pipeline.
//!
//! Subscribes to `EpochTrigger` events from the scheduler and executes the
//! complete pipeline for each trigger:
//!
//! 1. Fetch eligible members from DB
//! 2. Read user-submitted proof results from proof_submissions table
//! 3. Determine solvency statuses, detect changes
//! 4. Build Merkle tree for the epoch
//! 5. Record epoch in DB (on-chain publication via SP1 proof deferred)
//! 6. Update member statuses in DB
//! 7. Fire webhooks for status changes and epoch completion
//!
//! ## Privacy
//!
//! The agent never fetches balances directly. Users submit their own EIP-1186
//! proofs via `/submit_proof`, and the epoch processor reads the verified
//! results from the `proof_submissions` table.

use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tracing::{info, warn, error};

use crate::chain_publisher::OnChainPublisher;
use crate::db::Database;
use crate::merkle_service::{LeafInput, MerkleService};
use crate::proof_worker::ProofWorker;
use crate::rpc_fetcher::BalanceResult;
use crate::scheduler::EpochTrigger;
use crate::webhook::{StatusChange, WebhookService};

/// Result of processing a single epoch.
#[derive(Debug, Clone)]
pub struct EpochResult {
    pub policy_id_hex: String,
    pub epoch: u64,
    pub root: [u8; 32],
    pub member_count: u32,
    pub status_changes: Vec<StatusChange>,
    pub tx_hash: Option<String>,
}

/// The epoch processor that orchestrates the full pipeline.
pub struct EpochProcessor {
    db: Arc<Mutex<Database>>,
    proof_worker: Arc<ProofWorker>,
    publisher: Arc<OnChainPublisher>,
    webhook_svc: Arc<WebhookService>,
    /// If true, skip on-chain tx submission (DB-only mode for tests).
    skip_on_chain: bool,
}

impl EpochProcessor {
    /// Create a new epoch processor.
    pub fn new(
        db: Arc<Mutex<Database>>,
        proof_worker: Arc<ProofWorker>,
        publisher: Arc<OnChainPublisher>,
        webhook_svc: Arc<WebhookService>,
        skip_on_chain: bool,
    ) -> Self {
        Self {
            db,
            proof_worker,
            publisher,
            webhook_svc,
            skip_on_chain,
        }
    }

    /// Run the processor loop, consuming epoch triggers from the scheduler.
    ///
    /// Listens on a broadcast channel for `EpochTrigger` events and processes
    /// each one. Runs until the shutdown signal is received.
    pub async fn run(
        &self,
        mut trigger_rx: broadcast::Receiver<EpochTrigger>,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        info!("EpochProcessor started, waiting for triggers");

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("EpochProcessor received shutdown signal");
                    break;
                }
                trigger = trigger_rx.recv() => {
                    match trigger {
                        Ok(t) => {
                            info!(
                                policy_id = %t.policy_id_hex,
                                epoch = t.epoch,
                                block = t.block_number,
                                trusted_mode = t.trusted_mode,
                                "Processing epoch trigger"
                            );
                            match self.process_epoch(&t).await {
                                Ok(result) => {
                                    info!(
                                        policy_id = %result.policy_id_hex,
                                        epoch = result.epoch,
                                        member_count = result.member_count,
                                        status_changes = result.status_changes.len(),
                                        root = %hex::encode(result.root),
                                        "Epoch processed successfully"
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        policy_id = %t.policy_id_hex,
                                        epoch = t.epoch,
                                        error = %e,
                                        "Epoch processing failed"
                                    );
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("EpochProcessor lagged {n} triggers");
                        }
                        Err(_) => {
                            info!("Trigger channel closed, stopping EpochProcessor");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Process a single epoch trigger through the full pipeline.
    ///
    /// This is the core method that orchestrates all components.
    pub async fn process_epoch(&self, trigger: &EpochTrigger) -> Result<EpochResult> {
        if trigger.trusted_mode {
            self.process_trusted_epoch(trigger).await
        } else {
            self.process_zk_epoch(trigger).await
        }
    }

    /// Process a trusted-mode epoch (EIP-712 signature).
    async fn process_trusted_epoch(&self, trigger: &EpochTrigger) -> Result<EpochResult> {
        // 1. Fetch eligible members from DB
        let members = self.get_eligible_members(&trigger.policy_id_hex, trigger.epoch)?;

        if members.is_empty() {
            anyhow::bail!("No eligible members for policy {} at epoch {}",
                trigger.policy_id_hex, trigger.epoch);
        }

        info!(
            policy_id = %trigger.policy_id_hex,
            eligible_members = members.len(),
            "Fetched eligible members"
        );

        // 2. Determine statuses based on balance results
        //    For trusted mode in skip_on_chain (testing), we use the DB's last known balances.
        //    In production, the caller should have updated balances via RPC before triggering.
        let balance_results = self.fetch_balances_from_db(&members, trigger.threshold_wei)?;

        // 4. Detect status changes
        let status_changes = self.detect_status_changes(&members, &balance_results);

        // 5. Build leaf inputs for Merkle tree
        let leaf_inputs: Vec<LeafInput> = balance_results.iter()
            .map(|br| {
                let mut member_id = [0u8; 32];
                if let Ok(bytes) = hex::decode(&br.member_id_hex) {
                    if bytes.len() == 32 {
                        member_id.copy_from_slice(&bytes);
                    }
                }
                LeafInput {
                    member_id,
                    status: if br.is_solvent { 1 } else { 0 },
                    member_id_hex: br.member_id_hex.clone(),
                }
            })
            .collect();

        // 6. Build Merkle tree
        let tree_result = {
            let db = self.db.lock().unwrap();
            let merkle_svc = MerkleService::new(&db);
            merkle_svc.build_epoch_tree(
                &trigger.policy_id,
                trigger.epoch,
                &leaf_inputs,
                &trigger.policy_id_hex,
            )?
        };

        // 7. Sign with EIP-712 (trusted mode)
        let sig_result = self.proof_worker.sign_trusted_assertion(
            &trigger.policy_id,
            &tree_result.root,
            trigger.epoch,
            trigger.block_number,
            tree_result.member_count,
        ).await?;

        // 8. Publish on-chain or record in DB
        let publish_result = if self.skip_on_chain {
            self.publisher.record_epoch_only(
                &trigger.policy_id_hex,
                trigger.epoch,
                trigger.block_number,
                &tree_result.root,
                tree_result.member_count,
                None,
            )?
        } else {
            self.publisher.publish_trusted(
                &trigger.policy_id,
                &tree_result.root,
                trigger.epoch,
                trigger.block_number,
                tree_result.member_count,
                &sig_result.signature,
            ).await?
        };

        // 9. Update member statuses in DB
        self.update_member_statuses(&balance_results, trigger.block_number)?;

        // 10. Fire webhooks (non-blocking)
        let root_hex = hex::encode(tree_result.root);
        self.webhook_svc.fire_epoch_completed(
            &trigger.policy_id_hex,
            trigger.epoch,
            trigger.block_number,
            &root_hex,
            tree_result.member_count,
            publish_result.tx_hash.as_deref(),
        ).await;

        if !status_changes.is_empty() {
            self.webhook_svc.fire_status_changes(
                &trigger.policy_id_hex,
                trigger.epoch,
                &status_changes,
            ).await;
        }

        Ok(EpochResult {
            policy_id_hex: trigger.policy_id_hex.clone(),
            epoch: trigger.epoch,
            root: tree_result.root,
            member_count: tree_result.member_count,
            status_changes,
            tx_hash: publish_result.tx_hash,
        })
    }

    /// Process a ZK-mode epoch using user-submitted MPT proofs.
    ///
    /// In ZK mode, the agent never fetches balances itself. Instead, users submit
    /// their own EIP-1186 proofs via `/submit_proof`. The epoch processor reads
    /// these verified proof submissions from the DB to build the Merkle tree.
    ///
    /// Members who haven't submitted a proof for this epoch are marked insolvent (status=0).
    async fn process_zk_epoch(&self, trigger: &EpochTrigger) -> Result<EpochResult> {
        // 1. Fetch eligible members from DB
        let members = self.get_eligible_members(&trigger.policy_id_hex, trigger.epoch)?;

        if members.is_empty() {
            anyhow::bail!("No eligible members for policy {} at epoch {}",
                trigger.policy_id_hex, trigger.epoch);
        }

        info!(
            policy_id = %trigger.policy_id_hex,
            eligible_members = members.len(),
            "Fetched eligible members for ZK epoch"
        );

        // 2. Look up proof submissions for this epoch
        let submissions = {
            let db = self.db.lock().unwrap();
            db.get_proof_submissions_for_epoch(&trigger.policy_id_hex, trigger.epoch)?
        };

        // Build a lookup map: member_id -> submission
        let submission_map: std::collections::HashMap<String, &crate::db::ProofSubmissionRow> =
            submissions.iter().map(|s| (s.member_id.clone(), s)).collect();

        info!(
            policy_id = %trigger.policy_id_hex,
            submissions = submissions.len(),
            eligible = members.len(),
            "Proof submissions found for epoch"
        );

        // 3. Build balance results from submissions (missing = insolvent)
        let balance_results: Vec<BalanceResult> = members.iter()
            .map(|m| {
                if let Some(sub) = submission_map.get(&m.member_id) {
                    BalanceResult {
                        member_id_hex: m.member_id.clone(),
                        balance_wei: sub.balance_wei.parse().unwrap_or(0),
                        is_solvent: sub.is_solvent,
                    }
                } else {
                    // No proof submitted → insolvent
                    BalanceResult {
                        member_id_hex: m.member_id.clone(),
                        balance_wei: 0,
                        is_solvent: false,
                    }
                }
            })
            .collect();

        // 4. Detect status changes
        let status_changes = self.detect_status_changes(&members, &balance_results);

        // 5. Build leaf inputs for Merkle tree
        let leaf_inputs: Vec<LeafInput> = balance_results.iter()
            .map(|br| {
                let mut member_id = [0u8; 32];
                if let Ok(bytes) = hex::decode(&br.member_id_hex) {
                    if bytes.len() == 32 {
                        member_id.copy_from_slice(&bytes);
                    }
                }
                LeafInput {
                    member_id,
                    status: if br.is_solvent { 1 } else { 0 },
                    member_id_hex: br.member_id_hex.clone(),
                }
            })
            .collect();

        // 6. Build Merkle tree
        let tree_result = {
            let db = self.db.lock().unwrap();
            let merkle_svc = MerkleService::new(&db);
            merkle_svc.build_epoch_tree(
                &trigger.policy_id,
                trigger.epoch,
                &leaf_inputs,
                &trigger.policy_id_hex,
            )?
        };

        // 7. Record epoch in DB (on-chain publication deferred — SP1 proof generation not wired yet)
        let publish_result = self.publisher.record_epoch_only(
            &trigger.policy_id_hex,
            trigger.epoch,
            trigger.block_number,
            &tree_result.root,
            tree_result.member_count,
            None,
        )?;

        // 8. Update member statuses in DB
        self.update_member_statuses(&balance_results, trigger.block_number)?;

        // 9. Fire webhooks
        let root_hex = hex::encode(tree_result.root);
        self.webhook_svc.fire_epoch_completed(
            &trigger.policy_id_hex,
            trigger.epoch,
            trigger.block_number,
            &root_hex,
            tree_result.member_count,
            publish_result.tx_hash.as_deref(),
        ).await;

        if !status_changes.is_empty() {
            self.webhook_svc.fire_status_changes(
                &trigger.policy_id_hex,
                trigger.epoch,
                &status_changes,
            ).await;
        }

        Ok(EpochResult {
            policy_id_hex: trigger.policy_id_hex.clone(),
            epoch: trigger.epoch,
            root: tree_result.root,
            member_count: tree_result.member_count,
            status_changes,
            tx_hash: publish_result.tx_hash,
        })
    }

    // ── Helper methods ───────────────────────────────────────────────────────

    /// Get eligible members for a policy at the given epoch.
    ///
    /// A member is eligible if `effective_epoch <= epoch`.
    fn get_eligible_members(
        &self,
        policy_id_hex: &str,
        epoch: u64,
    ) -> Result<Vec<crate::db::MemberRow>> {
        let db = self.db.lock().unwrap();
        let all_members = db.get_members_for_policy(policy_id_hex)?;
        let eligible: Vec<_> = all_members
            .into_iter()
            .filter(|m| m.effective_epoch <= epoch)
            .collect();
        Ok(eligible)
    }

    /// Fetch balance information from the DB.
    ///
    /// Uses the DB's stored `last_balance_wei` (updated via proof submissions).
    fn fetch_balances_from_db(
        &self,
        members: &[crate::db::MemberRow],
        threshold_wei: u128,
    ) -> Result<Vec<BalanceResult>> {
        let mut results = Vec::with_capacity(members.len());
        for member in members {
            let balance: u128 = member.last_balance_wei.parse().unwrap_or(0);
            let is_solvent = balance >= threshold_wei;
            results.push(BalanceResult {
                member_id_hex: member.member_id.clone(),
                balance_wei: balance,
                is_solvent,
            });
        }
        Ok(results)
    }

    /// Detect status changes between current DB status and new balance results.
    fn detect_status_changes(
        &self,
        db_members: &[crate::db::MemberRow],
        balance_results: &[BalanceResult],
    ) -> Vec<StatusChange> {
        let mut changes = Vec::new();

        for (member, result) in db_members.iter().zip(balance_results.iter()) {
            let new_status = if result.is_solvent { "solvent" } else { "insolvent" };
            let old_status = &member.status;

            // A status change is when the old status differs from the new status,
            // excluding the initial "pending" → first status transition.
            if old_status != "pending" && old_status != new_status {
                changes.push(StatusChange {
                    member_id_hex: member.member_id.clone(),
                    old_status: old_status.clone(),
                    new_status: new_status.to_string(),
                });
            }
        }

        changes
    }

    /// Update member statuses in DB after epoch processing.
    fn update_member_statuses(
        &self,
        balance_results: &[BalanceResult],
        block_number: u64,
    ) -> Result<()> {
        let db = self.db.lock().unwrap();
        for result in balance_results {
            let status = if result.is_solvent { "solvent" } else { "insolvent" };
            db.update_member_status(
                &result.member_id_hex,
                status,
                &result.balance_wei.to_string(),
                block_number,
            )?;
        }
        Ok(())
    }
}

/// Helper to create an `EpochProcessor` with external balance injection.
///
/// This struct wraps `EpochProcessor` and allows tests to inject balance data
/// before processing an epoch, simulating the RPC fetch step.
pub struct EpochProcessorWithBalances {
    pub processor: EpochProcessor,
    pub db: Arc<Mutex<Database>>,
}

impl EpochProcessorWithBalances {
    /// Set a member's balance in the DB (simulating an RPC fetch).
    pub fn set_member_balance(&self, member_id_hex: &str, balance_wei: u128, block_number: u64) -> Result<()> {
        let db = self.db.lock().unwrap();
        // Determine status from balance (we don't have threshold here, so just store balance)
        let member = db.get_member(member_id_hex)?
            .context("Member not found")?;
        db.update_member_status(
            member_id_hex,
            &member.status, // Keep existing status, it will be updated during epoch processing
            &balance_wei.to_string(),
            block_number,
        )?;
        Ok(())
    }

    /// Process an epoch trigger.
    pub async fn process_epoch(&self, trigger: &EpochTrigger) -> Result<EpochResult> {
        self.processor.process_epoch(trigger).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_worker::ProofWorker;
    use alloy::signers::local::PrivateKeySigner;

    fn setup_test_components() -> (
        Arc<Mutex<Database>>,
        Arc<ProofWorker>,
        Arc<OnChainPublisher>,
        Arc<WebhookService>,
    ) {
        let db = Arc::new(Mutex::new(Database::open_in_memory().unwrap()));

        let signer = PrivateKeySigner::random();
        let key_hex = hex::encode(signer.credential().to_bytes());
        let proof_worker = Arc::new(
            ProofWorker::new(&key_hex, 1, "0x0000000000000000000000000000000000000001").unwrap()
        );

        // OnChainPublisher needs a valid RPC URL even for skip_on_chain mode.
        // Use a dummy URL — it won't actually be called.
        let publisher = Arc::new(
            OnChainPublisher::new(
                db.clone(),
                "http://localhost:8545",
                &key_hex,
                "0x0000000000000000000000000000000000000001",
                1,
            ).unwrap()
        );

        let webhook_svc = Arc::new(WebhookService::new(db.clone()));

        (db, proof_worker, publisher, webhook_svc)
    }

    fn make_test_trigger(policy_id_hex: &str, epoch: u64, block_number: u64) -> EpochTrigger {
        let mut policy_id = [0u8; 32];
        if let Ok(bytes) = hex::decode(policy_id_hex) {
            let len = bytes.len().min(32);
            policy_id[..len].copy_from_slice(&bytes[..len]);
        }

        EpochTrigger {
            policy_id_hex: policy_id_hex.to_string(),
            policy_id,
            epoch,
            block_number,
            threshold_wei: 1_000_000_000_000_000_000, // 1 ETH
            trusted_mode: true,
        }
    }

    #[tokio::test]
    async fn test_process_epoch_no_members() {
        let (db, proof_worker, publisher, webhook_svc) = setup_test_components();
        let processor = EpochProcessor::new(db, proof_worker, publisher, webhook_svc, true);

        let trigger = make_test_trigger("aabb", 1, 19_000_000);
        let result = processor.process_epoch(&trigger).await;

        // Should fail because no members are enrolled
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No eligible members"));
    }

    #[tokio::test]
    async fn test_process_trusted_epoch_basic() {
        let (db, proof_worker, publisher, webhook_svc) = setup_test_components();

        let policy_id_hex = hex::encode([0x01; 32]);

        // Enroll members (no wallet address stored)
        {
            let db = db.lock().unwrap();
            db.insert_member(
                &hex::encode([0xAA; 32]),
                &policy_id_hex,
                1700000000,
                1, // effective_epoch = 1
            ).unwrap();

            // Set balance to 5 ETH (solvent)
            db.update_member_status(
                &hex::encode([0xAA; 32]),
                "pending",
                "5000000000000000000",
                19_000_000,
            ).unwrap();

            db.insert_member(
                &hex::encode([0xBB; 32]),
                &policy_id_hex,
                1700000000,
                1,
            ).unwrap();

            // Set balance to 0.5 ETH (insolvent)
            db.update_member_status(
                &hex::encode([0xBB; 32]),
                "pending",
                "500000000000000000",
                19_000_000,
            ).unwrap();
        }

        let processor = EpochProcessor::new(
            db.clone(), proof_worker, publisher, webhook_svc, true, // skip_on_chain
        );

        let trigger = EpochTrigger {
            policy_id_hex: policy_id_hex.clone(),
            policy_id: [0x01; 32],
            epoch: 1,
            block_number: 19_000_100,
            threshold_wei: 1_000_000_000_000_000_000, // 1 ETH
            trusted_mode: true,
        };

        let result = processor.process_epoch(&trigger).await.unwrap();

        assert_eq!(result.epoch, 1);
        assert_eq!(result.member_count, 2);
        assert_ne!(result.root, [0u8; 32]);
        assert!(result.tx_hash.is_none()); // skip_on_chain

        // Verify DB was updated
        {
            let db = db.lock().unwrap();
            let member_a = db.get_member(&hex::encode([0xAA; 32])).unwrap().unwrap();
            assert_eq!(member_a.status, "solvent");

            let member_b = db.get_member(&hex::encode([0xBB; 32])).unwrap().unwrap();
            assert_eq!(member_b.status, "insolvent");

            // Verify epoch was recorded
            let epoch = db.get_latest_epoch(&policy_id_hex).unwrap().unwrap();
            assert_eq!(epoch.epoch, 1);
            assert_eq!(epoch.member_count, 2);
        }
    }

    #[tokio::test]
    async fn test_status_change_detection() {
        let (db, proof_worker, publisher, webhook_svc) = setup_test_components();

        let policy_id_hex = hex::encode([0x02; 32]);

        // Enroll member with initial solvent status (no wallet address stored)
        {
            let db = db.lock().unwrap();
            db.insert_member(
                &hex::encode([0xCC; 32]),
                &policy_id_hex,
                1700000000,
                1,
            ).unwrap();

            // Initially solvent with 5 ETH
            db.update_member_status(
                &hex::encode([0xCC; 32]),
                "solvent",
                "5000000000000000000",
                19_000_000,
            ).unwrap();
        }

        let processor = EpochProcessor::new(
            db.clone(), proof_worker, publisher, webhook_svc, true,
        );

        // Now drop balance below threshold → should detect status change
        {
            let db = db.lock().unwrap();
            db.update_member_status(
                &hex::encode([0xCC; 32]),
                "solvent", // Keep old status as solvent
                "100000000000000000", // 0.1 ETH — below threshold
                19_000_100,
            ).unwrap();
        }

        let trigger = EpochTrigger {
            policy_id_hex: policy_id_hex.clone(),
            policy_id: [0x02; 32],
            epoch: 2,
            block_number: 19_000_200,
            threshold_wei: 1_000_000_000_000_000_000,
            trusted_mode: true,
        };

        let result = processor.process_epoch(&trigger).await.unwrap();

        // Should detect the status change: solvent → insolvent
        assert_eq!(result.status_changes.len(), 1);
        assert_eq!(result.status_changes[0].old_status, "solvent");
        assert_eq!(result.status_changes[0].new_status, "insolvent");
    }

    #[tokio::test]
    async fn test_members_not_eligible_until_effective_epoch() {
        let (db, proof_worker, publisher, webhook_svc) = setup_test_components();

        let policy_id_hex = hex::encode([0x03; 32]);

        // Enroll a member with effective_epoch = 5 (no wallet address stored)
        {
            let db = db.lock().unwrap();
            db.insert_member(
                &hex::encode([0xDD; 32]),
                &policy_id_hex,
                1700000000,
                5, // Not eligible until epoch 5
            ).unwrap();
            db.update_member_status(
                &hex::encode([0xDD; 32]),
                "pending",
                "5000000000000000000",
                19_000_000,
            ).unwrap();
        }

        let processor = EpochProcessor::new(
            db.clone(), proof_worker, publisher, webhook_svc, true,
        );

        // Epoch 3 — member not yet eligible
        let trigger = EpochTrigger {
            policy_id_hex: policy_id_hex.clone(),
            policy_id: [0x03; 32],
            epoch: 3,
            block_number: 19_000_300,
            threshold_wei: 1_000_000_000_000_000_000,
            trusted_mode: true,
        };

        let result = processor.process_epoch(&trigger).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No eligible members"));
    }
}
