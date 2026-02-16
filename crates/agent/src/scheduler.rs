//! Epoch scheduler — triggers epoch updates per policy based on block intervals.
//!
//! The scheduler monitors block production and triggers an epoch update when
//! `current_block >= last_epoch_block + policy.epoch_length_blocks`.
//!
//! Each policy has its own scheduling cadence.

use anyhow::Result;
use tokio::sync::broadcast;
use tracing::{info, warn, error};

use crate::db::Database;
use crate::rpc_fetcher::RpcFetcher;

/// Configuration for a policy's epoch schedule.
#[derive(Debug, Clone)]
pub struct PolicySchedule {
    pub policy_id_hex: String,
    pub policy_id: [u8; 32],
    pub epoch_length_blocks: u64,
    pub threshold_wei: u128,
    pub trusted_mode: bool,
    pub active: bool,
}

/// An epoch update event emitted when an epoch is due for processing.
#[derive(Debug, Clone)]
pub struct EpochTrigger {
    pub policy_id_hex: String,
    pub policy_id: [u8; 32],
    pub epoch: u64,
    pub block_number: u64,
    pub threshold_wei: u128,
    pub trusted_mode: bool,
}

/// The scheduler that monitors block production and triggers epoch updates.
pub struct Scheduler {
    policies: Vec<PolicySchedule>,
    poll_interval_secs: u64,
}

impl Scheduler {
    /// Create a new scheduler with the given policies.
    pub fn new(policies: Vec<PolicySchedule>, poll_interval_secs: u64) -> Self {
        Self {
            policies,
            poll_interval_secs,
        }
    }

    /// Determine if an epoch update is due for a policy.
    ///
    /// Returns the next epoch number and the block to use for the update,
    /// or None if no update is needed yet.
    pub fn check_epoch_due(
        &self,
        policy: &PolicySchedule,
        current_block: u64,
        last_epoch_block: Option<u64>,
        last_epoch: Option<u64>,
    ) -> Option<EpochTrigger> {
        if !policy.active {
            return None;
        }

        let (next_epoch, epoch_due_at_block) = match (last_epoch, last_epoch_block) {
            (Some(epoch), Some(block)) => {
                let due_at = block + policy.epoch_length_blocks;
                (epoch + 1, due_at)
            }
            // No previous epoch — first epoch is due immediately
            _ => (1, 0),
        };

        if current_block >= epoch_due_at_block {
            Some(EpochTrigger {
                policy_id_hex: policy.policy_id_hex.clone(),
                policy_id: policy.policy_id,
                epoch: next_epoch,
                block_number: current_block,
                threshold_wei: policy.threshold_wei,
                trusted_mode: policy.trusted_mode,
            })
        } else {
            None
        }
    }

    /// Run the scheduler loop, checking for epoch triggers.
    ///
    /// Sends epoch triggers to the returned broadcast channel.
    /// The loop runs until the shutdown signal is received.
    pub async fn run(
        &self,
        rpc: &RpcFetcher,
        db: &Database,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<broadcast::Sender<EpochTrigger>> {
        let (trigger_tx, _) = broadcast::channel(32);
        let trigger_tx_clone = trigger_tx.clone();

        info!(
            policy_count = self.policies.len(),
            poll_interval_secs = self.poll_interval_secs,
            "Starting epoch scheduler"
        );

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("Scheduler received shutdown signal");
                    break;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(self.poll_interval_secs)) => {
                    // Poll for new blocks and check each policy
                    match rpc.get_block_number().await {
                        Ok(current_block) => {
                            for policy in &self.policies {
                                // Look up the latest epoch from the database
                                let latest = db.get_latest_epoch(&policy.policy_id_hex).ok().flatten();
                                let last_epoch = latest.as_ref().map(|e| e.epoch);
                                let last_block = latest.as_ref().map(|e| e.block_number);

                                if let Some(trigger) = self.check_epoch_due(
                                    policy,
                                    current_block,
                                    last_block,
                                    last_epoch,
                                ) {
                                    info!(
                                        policy_id = %trigger.policy_id_hex,
                                        epoch = trigger.epoch,
                                        block = trigger.block_number,
                                        "Epoch update triggered"
                                    );

                                    if trigger_tx.send(trigger).is_err() {
                                        // No active receivers — that's okay, pipeline might not be wired up yet
                                        warn!("No epoch trigger receivers");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to get block number");
                        }
                    }
                }
            }
        }

        Ok(trigger_tx_clone)
    }

    /// Get the number of configured policies.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> PolicySchedule {
        PolicySchedule {
            policy_id_hex: "0001".to_string(),
            policy_id: [0x01; 32],
            epoch_length_blocks: 100,
            threshold_wei: 1_000_000_000_000_000_000, // 1 ETH
            trusted_mode: true,
            active: true,
        }
    }

    #[test]
    fn test_first_epoch_triggers_immediately() {
        let scheduler = Scheduler::new(vec![test_policy()], 12);
        let policy = test_policy();

        let trigger = scheduler.check_epoch_due(&policy, 19_000_000, None, None);
        assert!(trigger.is_some());

        let trigger = trigger.unwrap();
        assert_eq!(trigger.epoch, 1);
        assert_eq!(trigger.block_number, 19_000_000);
    }

    #[test]
    fn test_epoch_not_due_yet() {
        let scheduler = Scheduler::new(vec![test_policy()], 12);
        let policy = test_policy();

        // Last epoch was at block 19_000_000, epoch_length is 100
        // Current block is 19_000_050 — not due yet (need 19_000_100)
        let trigger = scheduler.check_epoch_due(
            &policy,
            19_000_050,
            Some(19_000_000),
            Some(1),
        );
        assert!(trigger.is_none());
    }

    #[test]
    fn test_epoch_due() {
        let scheduler = Scheduler::new(vec![test_policy()], 12);
        let policy = test_policy();

        // Last epoch at block 19_000_000, epoch_length 100
        // Current block is 19_000_100 — epoch 2 is due
        let trigger = scheduler.check_epoch_due(
            &policy,
            19_000_100,
            Some(19_000_000),
            Some(1),
        );
        assert!(trigger.is_some());

        let trigger = trigger.unwrap();
        assert_eq!(trigger.epoch, 2);
        assert_eq!(trigger.block_number, 19_000_100);
    }

    #[test]
    fn test_inactive_policy_skipped() {
        let scheduler = Scheduler::new(vec![], 12);
        let mut policy = test_policy();
        policy.active = false;

        let trigger = scheduler.check_epoch_due(&policy, 19_000_000, None, None);
        assert!(trigger.is_none());
    }

    #[test]
    fn test_epoch_overdue() {
        let scheduler = Scheduler::new(vec![test_policy()], 12);
        let policy = test_policy();

        // Last epoch at block 19_000_000, epoch_length 100
        // Current block is 19_000_500 — way overdue, still triggers
        let trigger = scheduler.check_epoch_due(
            &policy,
            19_000_500,
            Some(19_000_000),
            Some(1),
        );
        assert!(trigger.is_some());
        assert_eq!(trigger.unwrap().epoch, 2);
    }
}
