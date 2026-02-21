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
use zk_pof_agent::merkle_service::{LeafInput, MerkleService};
use zk_pof_agent::rpc_fetcher::RpcFetcher;
use zk_pof_agent::proof_worker::ProofWorker;
use zk_pof_agent::chain_publisher::OnChainPublisher;

// ─── Application State ──────────────────────────────────────────────────────

/// Shared application state.
///
/// The Database is wrapped in a Mutex because rusqlite::Connection is not Sync.
/// Since our handlers are all async, we use a std::sync::Mutex (not tokio's)
/// since we don't hold it across await points.
struct AppState {
    db: Mutex<Database>,
    rpc_url: Option<String>,
    rpc_fetcher: Option<RpcFetcher>,
    proof_worker: Option<ProofWorker>,
    publisher: Option<OnChainPublisher>,
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

/// POST /admin/trigger_epoch/:policy_id — manually trigger an epoch for a policy.
///
/// This admin endpoint runs the full trusted-mode epoch pipeline:
/// 1. Fetch all eligible members
/// 2. Check balances via RPC
/// 3. Build Merkle tree
/// 4. Sign with EIP-712
/// 5. Publish on-chain (or DB-only if SKIP_ON_CHAIN=true)
/// 6. Update member statuses
async fn admin_trigger_epoch(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let rpc = match &state.rpc_fetcher {
        Some(r) => r,
        None => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "RPC not configured"})),
        ),
    };
    let proof_worker = match &state.proof_worker {
        Some(pw) => pw,
        None => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Proof worker not configured (need OPERATOR_PRIVATE_KEY)"})),
        ),
    };

    // 1. Fetch block number
    let block_number = match rpc.get_block_number().await {
        Ok(b) => b,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to get block number: {}", e)})),
        ),
    };

    // 2. Determine epoch and fetch members
    let (epoch, members_with_addresses, threshold_wei) = {
        let db = state.db.lock().unwrap();
        let current_epoch = db.get_latest_epoch(&policy_id)
            .ok()
            .flatten()
            .map(|e| e.epoch)
            .unwrap_or(0);
        let epoch = current_epoch + 1;

        // Fetch all members for this policy
        let members = match db.get_members_for_policy(&policy_id) {
            Ok(m) => m,
            Err(e) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("DB error: {}", e)})),
            ),
        };

        if members.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "No members enrolled in this policy"})),
            );
        }

        // For now, use a default threshold of 1 ETH (matches policy creation)
        let threshold: u128 = 1_000_000_000_000_000_000;

        let members_with_addrs: Vec<(String, String)> = members.iter()
            .filter(|m| m.effective_epoch <= epoch)
            .map(|m| (m.member_id.clone(), m.watch_target.clone()))
            .collect();

        if members_with_addrs.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("No eligible members at epoch {}", epoch)})),
            );
        }

        (epoch, members_with_addrs, threshold)
    };

    // 3. Fetch balances from RPC
    let mut leaf_inputs: Vec<LeafInput> = Vec::new();
    let mut balance_updates: Vec<(String, String, bool)> = Vec::new(); // (member_id, balance_str, solvent)

    for (member_id_hex, address) in &members_with_addresses {
        let balance: u128 = match rpc.get_balance(address).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(member_id = %member_id_hex, error = %e, "Failed to fetch balance, marking insolvent");
                0
            }
        };

        let is_solvent = balance >= threshold_wei;
        let status: u8 = if is_solvent { 1 } else { 0 };

        let mut member_id = [0u8; 32];
        if let Ok(bytes) = hex::decode(member_id_hex) {
            if bytes.len() == 32 {
                member_id.copy_from_slice(&bytes);
            }
        }

        leaf_inputs.push(LeafInput {
            member_id,
            status,
            member_id_hex: member_id_hex.clone(),
        });

        balance_updates.push((member_id_hex.clone(), balance.to_string(), is_solvent));
    }

    // 4. Parse policy_id bytes
    let policy_id_clean = policy_id.strip_prefix("0x").unwrap_or(&policy_id);
    let policy_id_bytes: [u8; 32] = match hex::decode(policy_id_clean) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid policy_id format"})),
        ),
    };

    // 5. Build Merkle tree
    let tree_result = {
        let db = state.db.lock().unwrap();
        let merkle_svc = MerkleService::new(&db);
        match merkle_svc.build_epoch_tree(&policy_id_bytes, epoch, &leaf_inputs, &policy_id) {
            Ok(r) => r,
            Err(e) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Merkle tree build failed: {}", e)})),
            ),
        }
    };

    // 6. Sign with EIP-712
    let sig_result = match proof_worker.sign_trusted_assertion(
        &policy_id_bytes,
        &tree_result.root,
        epoch,
        block_number,
        tree_result.member_count,
    ).await {
        Ok(s) => s,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("EIP-712 signing failed: {}", e)})),
        ),
    };

    // 7. Publish on-chain or record in DB
    let skip_on_chain = std::env::var("SKIP_ON_CHAIN")
        .map(|v| v == "true")
        .unwrap_or(false);

    let tx_hash = if skip_on_chain {
        // DB-only mode
        if let Some(ref publisher) = state.publisher {
            match publisher.record_epoch_only(
                &policy_id,
                epoch,
                block_number,
                &tree_result.root,
                tree_result.member_count,
                None,
            ) {
                Ok(r) => r.tx_hash,
                Err(e) => return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("DB record failed: {}", e)})),
                ),
            }
        } else {
            None
        }
    } else if let Some(ref publisher) = state.publisher {
        match publisher.publish_trusted(
            &policy_id_bytes,
            &tree_result.root,
            epoch,
            block_number,
            tree_result.member_count,
            &sig_result.signature,
        ).await {
            Ok(r) => r.tx_hash,
            Err(e) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("On-chain publish failed: {}", e)})),
            ),
        }
    } else {
        None
    };

    // 8. Update member statuses in DB
    {
        let db = state.db.lock().unwrap();
        for (member_id_hex, balance_str, is_solvent) in &balance_updates {
            let status = if *is_solvent { "solvent" } else { "insolvent" };
            if let Err(e) = db.update_member_status(member_id_hex, status, balance_str, block_number) {
                tracing::warn!(member_id = %member_id_hex, error = %e, "Failed to update member status");
            }
        }
    }

    info!(
        policy_id = %policy_id,
        epoch = epoch,
        member_count = tree_result.member_count,
        root = %hex::encode(tree_result.root),
        "Epoch triggered successfully"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "epoch": epoch,
            "block_number": block_number,
            "root": format!("0x{}", hex::encode(tree_result.root)),
            "member_count": tree_result.member_count,
            "tx_hash": tx_hash,
            "balance_updates": balance_updates.iter().map(|(id, bal_str, sol)| {
                serde_json::json!({
                    "member_id": id,
                    "balance_wei": bal_str,
                    "solvent": sol
                })
            }).collect::<Vec<_>>()
        })),
    )
}

// ─── App Setup ───────────────────────────────────────────────────────────────

/// Build the Axum router with all routes.
fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // System
        .route("/health", get(health))
        // Integrator endpoints
        .route("/enroll", post(enroll_handler))
        .route("/proof/:policy_id/:member_id", get(get_proof))
        .route("/status/:policy_id/:member_id", get(get_status))
        // Admin endpoints
        .route("/admin/members/:policy_id", get(admin_list_members))
        .route("/admin/epochs/:policy_id", get(admin_list_epochs))
        .route("/admin/trigger_epoch/:policy_id", post(admin_trigger_epoch))
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

    // Initialize RPC fetcher if URL is available
    let rpc_fetcher = rpc_url.as_ref().and_then(|url| {
        match RpcFetcher::new(url) {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create RPC fetcher");
                None
            }
        }
    });

    // Initialize proof worker if operator key is available
    let operator_key = std::env::var("OPERATOR_PRIVATE_KEY").ok();
    let oracle_address = std::env::var("ORACLE_ADDRESS").ok();
    let chain_id: u64 = std::env::var("CHAIN_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .unwrap_or(1);

    let proof_worker = match (&operator_key, &oracle_address) {
        (Some(key), Some(addr)) => {
            match ProofWorker::new(key, chain_id, addr) {
                Ok(pw) => {
                    info!("Proof worker initialized");
                    Some(pw)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to create proof worker");
                    None
                }
            }
        }
        _ => {
            info!("OPERATOR_PRIVATE_KEY or ORACLE_ADDRESS not set, epoch trigger disabled");
            None
        }
    };

    // Initialize on-chain publisher
    let db_arc = Arc::new(Mutex::new(db));
    let publisher = match (&rpc_url, &operator_key, &oracle_address) {
        (Some(url), Some(key), Some(addr)) => {
            match OnChainPublisher::new(db_arc.clone(), url, key, addr, chain_id) {
                Ok(p) => {
                    info!("On-chain publisher initialized");
                    Some(p)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to create on-chain publisher");
                    None
                }
            }
        }
        _ => None,
    };

    let state = Arc::new(AppState {
        db: Mutex::new(Database::open(&db_path).expect("Failed to reopen database")),
        rpc_url,
        rpc_fetcher,
        proof_worker,
        publisher,
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
