//! Webhook Service — delivers event notifications to registered endpoints.
//!
//! Fires webhooks for epoch completions and member status changes.
//! Delivery is fire-and-forget with exponential backoff retries.
//! Failures are logged but never block the epoch pipeline.

use std::sync::{Arc, Mutex};
use tracing::{info, warn, error};

use crate::db::Database;

/// Webhook service for delivering event notifications.
pub struct WebhookService {
    db: Arc<Mutex<Database>>,
    client: reqwest::Client,
}

/// A status change detected during an epoch.
#[derive(Debug, Clone)]
pub struct StatusChange {
    pub member_id_hex: String,
    pub old_status: String,
    pub new_status: String,
}

/// Webhook event payload (JSON-serializable).
#[derive(Debug, Clone, serde::Serialize)]
pub struct WebhookEventPayload {
    pub event: String,
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_status: Option<String>,
    pub timestamp: String,
}

impl WebhookService {
    /// Create a new webhook service.
    pub fn new(db: Arc<Mutex<Database>>) -> Self {
        Self {
            db,
            client: reqwest::Client::new(),
        }
    }

    /// Create a webhook service with a custom HTTP client (for testing).
    #[cfg(test)]
    pub fn with_client(db: Arc<Mutex<Database>>, client: reqwest::Client) -> Self {
        Self { db, client }
    }

    /// Fire an "epoch.completed" webhook for all registered endpoints.
    ///
    /// This is fire-and-forget: failures are logged but never block the pipeline.
    pub async fn fire_epoch_completed(
        &self,
        policy_id_hex: &str,
        epoch: u64,
        block_number: u64,
        root_hex: &str,
        member_count: u32,
        tx_hash: Option<&str>,
    ) {
        let payload = WebhookEventPayload {
            event: "epoch.completed".to_string(),
            policy_id: policy_id_hex.to_string(),
            epoch: Some(epoch),
            block_number: Some(block_number),
            root: Some(root_hex.to_string()),
            member_count: Some(member_count),
            tx_hash: tx_hash.map(|s| s.to_string()),
            member_id: None,
            old_status: None,
            new_status: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        self.deliver_to_subscribers(policy_id_hex, "epoch.completed", &payload).await;
    }

    /// Fire "member.status_changed" webhooks for detected status changes.
    ///
    /// This is fire-and-forget: failures are logged but never block the pipeline.
    pub async fn fire_status_changes(
        &self,
        policy_id_hex: &str,
        epoch: u64,
        changes: &[StatusChange],
    ) {
        for change in changes {
            let payload = WebhookEventPayload {
                event: "member.status_changed".to_string(),
                policy_id: policy_id_hex.to_string(),
                epoch: Some(epoch),
                block_number: None,
                root: None,
                member_count: None,
                tx_hash: None,
                member_id: Some(change.member_id_hex.clone()),
                old_status: Some(change.old_status.clone()),
                new_status: Some(change.new_status.clone()),
                timestamp: chrono::Utc::now().to_rfc3339(),
            };

            self.deliver_to_subscribers(policy_id_hex, "member.status_changed", &payload).await;
        }
    }

    /// Deliver a webhook payload to all registered subscribers for this event.
    async fn deliver_to_subscribers(
        &self,
        policy_id_hex: &str,
        event_type: &str,
        payload: &WebhookEventPayload,
    ) {
        // Fetch webhook URLs from DB (lock briefly, then release)
        let webhooks = {
            let db = self.db.lock().unwrap();
            match db.get_webhooks_for_policy(policy_id_hex) {
                Ok(hooks) => hooks,
                Err(e) => {
                    error!(error = %e, "Failed to fetch webhooks from DB");
                    return;
                }
            }
        };

        for hook in &webhooks {
            // Only deliver if the webhook is subscribed to this event type
            if !hook.events.split(',').any(|e| e.trim() == event_type) {
                continue;
            }

            let url = hook.url.clone();
            let payload = payload.clone();
            let client = self.client.clone();

            // Spawn delivery as a separate task so it never blocks the pipeline
            tokio::spawn(async move {
                if let Err(e) = send_with_retries(&client, &url, &payload, 3).await {
                    error!(
                        url = %url,
                        event = %payload.event,
                        error = %e,
                        "Webhook delivery failed after retries"
                    );
                }
            });
        }
    }
}

/// Send a webhook payload with exponential backoff retries.
///
/// Retries on network errors and 5xx responses. Does not retry on 4xx.
async fn send_with_retries(
    client: &reqwest::Client,
    url: &str,
    payload: &WebhookEventPayload,
    max_retries: u32,
) -> Result<(), String> {
    let mut delay_secs = 1u64;

    for attempt in 0..=max_retries {
        match client.post(url).json(payload).send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    info!(url = %url, event = %payload.event, "Webhook delivered");
                    return Ok(());
                }
                if status.is_client_error() {
                    // Don't retry 4xx errors
                    return Err(format!("Webhook returned {status}"));
                }
                // 5xx — retry
                warn!(
                    url = %url,
                    status = %status,
                    attempt = attempt,
                    "Webhook returned server error, retrying"
                );
            }
            Err(e) => {
                warn!(
                    url = %url,
                    attempt = attempt,
                    error = %e,
                    "Webhook request failed, retrying"
                );
            }
        }

        if attempt < max_retries {
            tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;
            delay_secs *= 2; // exponential backoff: 1s, 2s, 4s
        }
    }

    Err(format!("Webhook delivery failed after {max_retries} retries"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_payload_serialization() {
        let payload = WebhookEventPayload {
            event: "epoch.completed".to_string(),
            policy_id: "aabbccdd".to_string(),
            epoch: Some(42),
            block_number: Some(19_000_000),
            root: Some("eeff0011".to_string()),
            member_count: Some(10),
            tx_hash: Some("0xdeadbeef".to_string()),
            member_id: None,
            old_status: None,
            new_status: None,
            timestamp: "2025-07-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"event\":\"epoch.completed\""));
        assert!(json.contains("\"epoch\":42"));
        // None fields should be omitted
        assert!(!json.contains("member_id"));
        assert!(!json.contains("old_status"));
    }

    #[test]
    fn test_status_change_payload() {
        let payload = WebhookEventPayload {
            event: "member.status_changed".to_string(),
            policy_id: "aabb".to_string(),
            epoch: Some(5),
            block_number: None,
            root: None,
            member_count: None,
            tx_hash: None,
            member_id: Some("member_001".to_string()),
            old_status: Some("solvent".to_string()),
            new_status: Some("insolvent".to_string()),
            timestamp: "2025-07-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"member.status_changed\""));
        assert!(json.contains("\"old_status\":\"solvent\""));
        assert!(json.contains("\"new_status\":\"insolvent\""));
    }
}
