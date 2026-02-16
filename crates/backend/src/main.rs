//! Solvency Agent API server.
//!
//! HTTP endpoints for the Solvency Agent middleware.
//! Built with Axum, serves enrollment, proof serving, status, and admin APIs.
//!
//! ## Endpoints
//!
//! Integrator:
//!   POST /enroll                        — enroll a new member
//!   GET  /proof/{policyId}/{memberId}   — get Merkle membership proof
//!   GET  /status/{policyId}/{memberId}  — get member status
//!
//! Admin:
//!   GET  /admin/members/{policyId}      — list members for a policy
//!   GET  /admin/epochs/{policyId}       — list epoch history
//!
//! System:
//!   GET /health                         — health check

use axum::{
    Router,
    extract::{Path, State, Json},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tracing::info;
use tracing_subscriber::EnvFilter;

use zk_pof_agent::db::Database;
use zk_pof_agent::merkle_service::MerkleService;

// ─── Application State ──────────────────────────────────────────────────────

/// Shared application state.
///
/// The Database is wrapped in a Mutex because rusqlite::Connection is not Sync.
/// Since our handlers are all async, we use a std::sync::Mutex (not tokio's)
/// since we don't hold it across await points.
struct AppState {
    db: Mutex<Database>,
    #[allow(dead_code)] // Will be used when balance checking is wired up
    rpc_url: Option<String>,
}

// ─── Request / Response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct EnrollRequest {
    policy_id: String,
    wallet_address: String,
    signature: String, // hex-encoded 65-byte signature
    signed_message: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// GET /health — health check
async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// POST /enroll — enroll a new member
///
/// For Phase 1 MVP, enrollment requires an RPC URL to check balance.
/// The actual enrollment logic validates signature, checks balance, and stores the member.
///
/// Note: Enrollment with RPC-based balance checking requires async calls.
/// For the MVP, we perform signature verification and member ID computation
/// synchronously and defer balance checking to the epoch update cycle.
async fn enroll_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    use std::time::{SystemTime, UNIX_EPOCH};

    // 1. Decode the signature from hex
    let sig_hex = req.signature.strip_prefix("0x").unwrap_or(&req.signature);
    let signature = match hex::decode(sig_hex) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid signature hex: {}", e)})),
            );
        }
    };

    // 2. Verify signed message format
    if !req.signed_message.starts_with("zkpof-holder-v1:") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid message format: must start with 'zkpof-holder-v1:'"})),
        );
    }

    // 3. Verify ECDSA signature recovers to claimed address
    let wallet_hex = req.wallet_address.strip_prefix("0x")
        .unwrap_or(&req.wallet_address);

    match zk_pof_agent::enrollment::recover_address(&req.signed_message, &signature) {
        Ok(recovered) => {
            let recovered_hex = hex::encode(recovered);
            if recovered_hex.to_lowercase() != wallet_hex.to_lowercase() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!(
                            "Signature verification failed: recovered 0x{} but claimed 0x{}",
                            recovered_hex, wallet_hex
                        )
                    })),
                );
            }
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Signature recovery failed: {}", e)})),
            );
        }
    }

    // 4. Compute memberId = SHA256(signature)
    let member_id = zk_pof_agent::enrollment::compute_member_id(&signature);
    let member_id_hex = hex::encode(member_id);

    // 5. Get current epoch and store member (db operations don't cross await)
    let db = state.db.lock().unwrap();

    // Check if already enrolled
    if let Ok(Some(existing)) = db.get_member(&member_id_hex) {
        if existing.policy_id == req.policy_id {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!("Member {} is already enrolled in policy {}", member_id_hex, req.policy_id)
                })),
            );
        }
    }

    let current_epoch = db.get_latest_epoch(&req.policy_id)
        .ok()
        .flatten()
        .map(|e| e.epoch)
        .unwrap_or(0);

    let effective_epoch = current_epoch + 1;
    let enrolled_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    match db.insert_member(
        &member_id_hex,
        &req.wallet_address,
        &req.policy_id,
        enrolled_at,
        effective_epoch,
    ) {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "member_id": member_id_hex,
                "status": "enrolled",
                "effective_epoch": effective_epoch
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to store member: {}", e)})),
        ),
    }
}

/// GET /proof/:policy_id/:member_id — get Merkle membership proof
async fn get_proof(
    State(state): State<Arc<AppState>>,
    Path((policy_id, member_id)): Path<(String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db = state.db.lock().unwrap();

    // 1. Look up the member
    let member = match db.get_member(&member_id) {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Member not found"})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Database error: {}", e)})),
            );
        }
    };

    // 2. Get the latest epoch for this policy
    let latest_epoch = match db.get_latest_epoch(&policy_id) {
        Ok(Some(e)) => e,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "No epochs found for this policy"})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Database error: {}", e)})),
            );
        }
    };

    // 3. Parse member_id and policy_id from hex
    let member_id_bytes = match hex::decode(&member_id) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid member_id (must be 32 hex bytes)"})),
            );
        }
    };

    let policy_id_clean = policy_id.strip_prefix("0x").unwrap_or(&policy_id);
    let policy_id_bytes = match hex::decode(policy_id_clean) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid policy_id (must be 32 hex bytes)"})),
            );
        }
    };

    // 4. Determine the member's status byte
    let status_byte = match member.status.as_str() {
        "solvent" => 1u8,
        _ => 0u8,
    };

    // 5. Generate the Merkle proof
    let merkle_svc = MerkleService::new(&db);
    match merkle_svc.get_member_proof(
        &policy_id,
        latest_epoch.epoch,
        &member_id,
        &member_id_bytes,
        status_byte,
        &policy_id_bytes,
    ) {
        Ok(proof) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "member_id": member_id,
                "policy_id": policy_id,
                "status": proof.status,
                "epoch": proof.epoch,
                "leaf_index": proof.leaf_index,
                "merkle_proof": proof.merkle_proof.iter().map(hex::encode).collect::<Vec<_>>(),
                "root": hex::encode(proof.root),
                "block_number": latest_epoch.block_number
            })),
        ),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Could not generate proof: {}", e)})),
        ),
    }
}

/// GET /status/:policy_id/:member_id — get member status
async fn get_status(
    State(state): State<Arc<AppState>>,
    Path((policy_id, member_id)): Path<(String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db = state.db.lock().unwrap();

    match db.get_member(&member_id) {
        Ok(Some(m)) => {
            if m.policy_id != policy_id {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "Member not found for this policy"})),
                );
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "member_id": m.member_id,
                    "policy_id": m.policy_id,
                    "status": m.status,
                    "last_balance_wei": m.last_balance_wei,
                    "last_checked_block": m.last_checked_block,
                    "effective_epoch": m.effective_epoch,
                    "enrolled_at": m.enrolled_at
                })),
            )
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Member not found"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Database error: {}", e)})),
        ),
    }
}

/// GET /admin/members/:policy_id — list all members for a policy
async fn admin_list_members(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db = state.db.lock().unwrap();

    match db.get_members_for_policy(&policy_id) {
        Ok(members) => {
            let items: Vec<serde_json::Value> = members.iter().map(|m| {
                serde_json::json!({
                    "member_id": m.member_id,
                    "status": m.status,
                    "last_balance_wei": m.last_balance_wei,
                    "last_checked_block": m.last_checked_block,
                    "effective_epoch": m.effective_epoch,
                })
            }).collect();

            (StatusCode::OK, Json(serde_json::json!({
                "policy_id": policy_id,
                "member_count": items.len(),
                "members": items
            })))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Database error: {}", e)})),
        ),
    }
}

/// GET /admin/epochs/:policy_id — list epoch history for a policy
async fn admin_list_epochs(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db = state.db.lock().unwrap();

    match db.get_latest_epoch(&policy_id) {
        Ok(Some(epoch)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "policy_id": policy_id,
                "latest_epoch": {
                    "epoch": epoch.epoch,
                    "block_number": epoch.block_number,
                    "root": epoch.root,
                    "member_count": epoch.member_count,
                    "published_at_block": epoch.published_at_block
                }
            })),
        ),
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "policy_id": policy_id,
                "latest_epoch": null
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Database error: {}", e)})),
        ),
    }
}

// ─── App Setup ───────────────────────────────────────────────────────────────

/// Build the Axum router with all routes.
fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // System
        .route("/health", get(health))
        // Integrator endpoints
        .route("/enroll", post(enroll_handler))
        .route("/proof/{policy_id}/{member_id}", get(get_proof))
        .route("/status/{policy_id}/{member_id}", get(get_status))
        // Admin endpoints
        .route("/admin/members/{policy_id}", get(admin_list_members))
        .route("/admin/epochs/{policy_id}", get(admin_list_epochs))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .init();

    info!("Starting Solvency Agent API server");

    // Open database
    let db_path = std::env::var("DATABASE_PATH")
        .unwrap_or_else(|_| "solvency_agent.db".to_string());

    let db = Database::open(&db_path)
        .expect("Failed to open database");

    info!(db_path = %db_path, "Database opened");

    // Check for RPC URL
    let rpc_url = match std::env::var("RPC_URL") {
        Ok(url) => {
            info!(rpc_url = %url, "RPC URL configured");
            Some(url)
        }
        Err(_) => {
            info!("RPC_URL not set, enrollment will be unavailable");
            None
        }
    };

    let state = Arc::new(AppState {
        db: Mutex::new(db),
        rpc_url,
    });
    let app = build_router(state);

    let bind_addr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    info!(bind = %bind_addr, "Listening");

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}
