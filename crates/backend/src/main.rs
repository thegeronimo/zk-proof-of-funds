//! Solvency Agent API server.
//!
//! HTTP endpoints for the Solvency Agent middleware.
//! Built with Axum, serves enrollment, proof serving, status, and admin APIs.
//!
//! ## Privacy
//!
//! The agent never stores wallet addresses. Users submit their own EIP-1186
//! proofs via `/submit_proof`, and the agent only retains the memberId.
//!
//! ## Endpoints
//!
//! Integrator:
//!   POST /enroll                                  — enroll a new member (no address needed)
//!   POST /submit_proof/:policy_id/:member_id      — submit an MPT proof for solvency
//!   GET  /proof/:policy_id/:member_id             — get Merkle membership proof
//!   GET  /status/:policy_id/:member_id            — get member status
//!
//! Privacy V2 (PRIVACY_V2.md):
//!   POST /v2/enroll                               — enroll with a deterministic nullifier + DLEQ proof
//!   GET  /v2/solvent_set/:policy_id               — latest solvent-set root metadata
//!   GET  /v2/solvent_set/:policy_id/leaves        — the public address list (paginated);
//!                                                   clients compute membership paths locally
//!   POST /v2/admin/build_solvent_set/:policy_id   — build a solvent set for the next epoch
//!
//! Admin:
//!   GET  /admin/members/:policy_id                — list members for a policy
//!   GET  /admin/epochs/:policy_id                 — list epoch history
//!   POST /admin/trigger_epoch/:policy_id          — manually trigger an epoch
//!
//! System:
//!   GET /health                                   — health check
//!
//! ## Operator authentication
//!
//! Every `/admin/*` and `/v2/admin/*` route sits behind a bearer token from
//! `ZKPOF_ADMIN_TOKEN` (see [`require_operator`]). These routes build and
//! publish the sets that relying protocols trust, so leaving them open — as
//! they were before the 2026-07 review — let anyone trigger epochs or
//! reshape a policy's set. The token is the minimum bar; the control plane is
//! designed so mTLS or signed operator requests can replace it without
//! touching handlers. The server refuses to start with admin routes exposed
//! and no token configured unless `ZKPOF_DEV_INSECURE_ADMIN=1` is set.

use axum::{
    Router,
    extract::{Path, Query, State, Json},
    http::{HeaderMap, StatusCode},
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
use zk_pof_agent::enrollment::{parse_policy_id, register_nullifier_member, NullifierEnrollment};
use zk_pof_agent::solvent_set_service::SolventSetService;

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
    /// Bearer token guarding the operator control plane. `None` only in the
    /// explicitly-acknowledged dev mode.
    admin_token: Option<String>,
    /// Reads authoritative policy parameters from the chain. `None` leaves the
    /// backend in unpinned dev mode, where a build must state its own terms.
    policy_reader: Option<zk_pof_agent::policy_reader::PolicyReader>,
}

/// Gate an operator route on the configured bearer token.
///
/// Returns `Err` with the response to send when the caller is not authorized;
/// handlers use `?`-style early return. Comparison is length-checked and
/// constant-time-ish (the token is not a password, but there is no reason to
/// leak its length through timing).
fn require_operator(
    state: &AppState,
    headers: &HeaderMap,
    action: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let Some(expected) = state.admin_token.as_deref() else {
        // Dev mode: explicitly acknowledged at startup.
        tracing::warn!(action, "Operator action served without authentication (dev mode)");
        return Ok(());
    };

    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();

    let ok = presented.len() == expected.len()
        && presented
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;

    if ok {
        // Audit log: who did what, when. Operator actions reshape the sets
        // relying protocols depend on, so they are never silent.
        tracing::info!(action, "Operator action authorized");
        Ok(())
    } else {
        tracing::warn!(action, "Rejected unauthorized operator action");
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Operator authentication required",
                "hint": "Send 'Authorization: Bearer <ZKPOF_ADMIN_TOKEN>'"
            })),
        ))
    }
}

/// Mirrors that serve a policy's snapshot, from `ZKPOF_SNAPSHOT_MIRRORS`
/// (comma-separated base URLs).
///
/// A root nobody can fetch the leaves for is a root no member can prove
/// against, so publication should always come with somewhere to get the data
/// (review §4.4). `{policy}` and `{epoch}` are substituted if present.
fn parse_address_bytes(value: &str) -> anyhow::Result<[u8; 20]> {
    let clean = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(clean).map_err(|e| anyhow::anyhow!("not hex: {e}"))?;
    if bytes.len() != 20 {
        anyhow::bail!("expected 20 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn snapshot_mirrors(policy_id: &str, epoch: u64) -> Vec<String> {
    std::env::var("ZKPOF_SNAPSHOT_MIRRORS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|base| {
            base.replace("{policy}", policy_id)
                .replace("{epoch}", &epoch.to_string())
        })
        .collect()
}

// ─── Request / Response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct EnrollRequest {
    policy_id: String,
    signature: String, // hex-encoded 65-byte signature
    signed_message: String,
}

/// Request body for submitting an MPT proof.
///
/// `trie_key` (= keccak256(address), computed client-side) is the supported
/// field: the plaintext address never transits the agent. `wallet_address` is
/// **deprecated and rejected by default** — set
/// `ZKPOF_ALLOW_PLAINTEXT_ADDRESS=1` to re-enable it for un-migrated
/// integrators (PRIVACY_V2.md §7).
#[derive(Debug, Deserialize)]
struct SubmitProofRequest {
    #[serde(default)]
    wallet_address: Option<String>, // legacy: used transiently, NOT stored
    #[serde(default)]
    trie_key: Option<String>,       // preferred: keccak256(address), hex 32 bytes
    proof_nodes: Vec<String>,       // hex-encoded RLP proof nodes from eth_getProof
    block_number: u64,              // block the proof references
}

/// Request body for V2 (nullifier) enrollment. See PRIVACY_V2.md §3.
#[derive(Debug, Deserialize)]
struct EnrollV2Request {
    policy_id: String,   // 32-byte hex (0x optional)
    #[serde(default)]
    scope_hash: Option<String>, // 32-byte hex; defaults to the policy's own scope
    public_key: String,  // 33-byte compressed secp256k1 point, hex
    nullifier: String,   // 33-byte compressed nullifier point, hex
    dleq_a: String,      // DLEQ commitment A, 33-byte hex
    dleq_b: String,      // DLEQ commitment B, 33-byte hex
    dleq_s: String,      // DLEQ response s, 32-byte hex
}

/// Query parameters for the solvent-set leaves endpoint.
#[derive(Debug, Deserialize)]
struct SolventSetLeavesQuery {
    epoch: Option<u64>,
    offset: Option<usize>,
    limit: Option<usize>,
}

/// Request body for building a solvent set (admin).
#[derive(Debug, Deserialize)]
struct BuildSolventSetRequest {
    /// Explicit candidate addresses to consider.
    #[serde(default)]
    candidates: Vec<String>,
    /// Reference block for balance sampling. Defaults to a blockhash-derived
    /// unpredictable block within the last `maxBlockAge / 2` blocks.
    #[serde(default)]
    block_number: Option<u64>,
    /// Threshold in wei as a decimal string (defaults to 1 ETH).
    #[serde(default)]
    threshold_wei: Option<String>,
    /// ERC-20 token to check (native ETH when omitted).
    #[serde(default)]
    token_address: Option<String>,
    /// With `token_address`: also discover candidates from Transfer logs in
    /// this inclusive block range.
    #[serde(default)]
    discover_from_block: Option<u64>,
    #[serde(default)]
    discover_to_block: Option<u64>,
    /// Stage B: verify per-candidate EIP-1186 proofs via the derivation
    /// statement (native pre-check of the SP1 program). With `token_address`,
    /// candidate balances are proven via storage proofs and `balance_slot`
    /// is required.
    #[serde(default)]
    proven: bool,
    /// ERC-20 proven mode: the Solidity mapping slot of `balanceOf`.
    #[serde(default)]
    balance_slot: Option<u64>,
    /// Abort rather than publish a set with unresolved candidates (default
    /// `true`). An RPC failure is not evidence of insolvency, so silently
    /// dropping the candidate would understate the set and give an operator
    /// deniable censorship. Set `false` to deliberately publish a partial set.
    #[serde(default)]
    strict: Option<bool>,
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
/// In ZK privacy mode, enrollment only requires a valid ECDSA signature.
/// No wallet address is sent to or stored by the agent.
/// The memberId = SHA256(signature) is the only identifier stored.
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

    // 3. Verify ECDSA signature is valid (recovers to some non-zero address)
    //    We do NOT compare to a claimed address — the agent never learns the address.
    match zk_pof_agent::enrollment::recover_address(&req.signed_message, &signature) {
        Ok(_recovered) => {
            // Signature is valid — that's all we need to know.
            // The recovered address is discarded immediately.
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
    if let Ok(Some(_existing)) = db.get_member_for_policy(&member_id_hex, &req.policy_id) {
        {
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

    // No wallet address stored — only memberId and policyId
    match db.insert_member(
        &member_id_hex,
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

/// POST /submit_proof/:policy_id/:member_id — submit an MPT proof for solvency verification.
///
/// Users fetch their own `eth_getProof` from any Ethereum node and submit it here.
/// The agent verifies the MPT proof against the state root for the given block,
/// extracts the balance, and stores the verified result.
///
/// The wallet_address is used ONLY for MPT verification (computing keccak256(address)
/// as the trie key) and is immediately discarded — it is NEVER stored.
async fn submit_proof_handler(
    State(state): State<Arc<AppState>>,
    Path((policy_id, member_id)): Path<(String, String)>,
    Json(req): Json<SubmitProofRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let (policy_id, member_id) = (canonical_hex(&policy_id), canonical_hex(&member_id));

    // 1. Verify member exists
    {
        let db = state.db.lock().unwrap();
        match db.get_member(&member_id) {
            Ok(Some(m)) => {
                if m.policy_id != policy_id {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({"error": "Member not found for this policy"})),
                    );
                }
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "Member not found — enroll first"})),
                );
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Database error: {}", e)})),
                );
            }
        }
    }

    // 2. Get state root for the given block from RPC
    let rpc = match &state.rpc_fetcher {
        Some(r) => r,
        None => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "RPC not configured"})),
        ),
    };

    let state_root = match rpc.get_state_root(req.block_number).await {
        Ok(sr) => sr,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Failed to get state root for block {}: {}", req.block_number, e)})),
        ),
    };

    // 3. Resolve the trie key — preferably supplied directly (the plaintext
    //    address then never transits the agent); legacy callers still send
    //    the address, which is used transiently and NOT stored.
    let trie_key: [u8; 32] = match (&req.trie_key, &req.wallet_address) {
        (Some(key_hex), _) => {
            let clean = key_hex.strip_prefix("0x").unwrap_or(key_hex);
            match hex::decode(clean) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid trie_key (must be 32 bytes hex)"})),
                ),
            }
        }
        (None, Some(address_hex)) => {
            // Deprecated path: accepting a plaintext address makes privacy a
            // retention promise again, so it is opt-in per deployment.
            if std::env::var("ZKPOF_ALLOW_PLAINTEXT_ADDRESS").ok().as_deref() != Some("1") {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "wallet_address is deprecated — send trie_key (keccak256 of the address, computed client-side). Set ZKPOF_ALLOW_PLAINTEXT_ADDRESS=1 to re-enable the legacy field."
                    })),
                );
            }
            tracing::warn!("Deprecated wallet_address used in /submit_proof — migrate to trie_key");
            let clean = address_hex.strip_prefix("0x").unwrap_or(address_hex);
            match hex::decode(clean) {
                Ok(b) if b.len() == 20 => {
                    let mut arr = [0u8; 20];
                    arr.copy_from_slice(&b);
                    zk_pof_common::mpt::account_trie_key(&arr)
                }
                _ => return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid wallet_address (must be 20 bytes hex)"})),
                ),
            }
        }
        (None, None) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Provide trie_key (keccak256 of the address, computed client-side)"})),
        ),
    };

    // 4. Decode proof nodes from hex
    let proof_nodes: Vec<Vec<u8>> = match req.proof_nodes.iter()
        .map(|n| {
            let hex_str = n.strip_prefix("0x").unwrap_or(n);
            hex::decode(hex_str)
        })
        .collect::<std::result::Result<Vec<Vec<u8>>, _>>()
    {
        Ok(nodes) => nodes,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid proof_nodes hex: {}", e)})),
        ),
    };

    // 5. Verify MPT proof by trie key — no address needed for verification.
    let balance_bytes = match zk_pof_common::mpt::verify_account_balance_with_key(
        &state_root,
        &trie_key,
        &proof_nodes,
    ) {
        Ok(b) => b,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("MPT proof verification failed: {}", e)})),
        ),
    };
    // Neither the trie key nor any address is stored

    // 6. Convert balance to u128 and check threshold
    let threshold_wei: u128 = 1_000_000_000_000_000_000; // 1 ETH (TODO: read from policy)
    let is_solvent = zk_pof_agent::mpt_verifier::balance_meets_threshold(&balance_bytes, threshold_wei);

    // Convert balance bytes to decimal string
    let balance_u128 = {
        let mut val: u128 = 0;
        for &b in &balance_bytes[16..] {
            val = val << 8 | b as u128;
        }
        val
    };
    let balance_str = balance_u128.to_string();

    // 7. Determine epoch
    let epoch = {
        let db = state.db.lock().unwrap();
        let current_epoch = db.get_latest_epoch(&policy_id)
            .ok()
            .flatten()
            .map(|e| e.epoch)
            .unwrap_or(0);
        current_epoch + 1
    };

    // 8. Store proof submission in DB (NO wallet address stored)
    {
        let db = state.db.lock().unwrap();
        if let Err(e) = db.insert_proof_submission(
            &member_id,
            &policy_id,
            epoch,
            req.block_number,
            &balance_str,
            is_solvent,
        ) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to store proof: {}", e)})),
            );
        }

        // Also update member's last balance and block
        let status_str = if is_solvent { "solvent" } else { "insolvent" };
        let _ = db.update_member_status(&member_id, status_str, &balance_str, req.block_number);
    }

    info!(
        member_id = %member_id,
        policy_id = %policy_id,
        epoch = epoch,
        balance = %balance_str,
        solvent = is_solvent,
        "Proof submitted and verified"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "member_id": member_id,
            "policy_id": policy_id,
            "epoch": epoch,
            "block_number": req.block_number,
            "balance_wei": balance_str,
            "is_solvent": is_solvent,
            "status": if is_solvent { "solvent" } else { "insolvent" }
        })),
    )
}

/// GET /proof/:policy_id/:member_id — get Merkle membership proof
async fn get_proof(
    State(state): State<Arc<AppState>>,
    Path((policy_id, member_id)): Path<(String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    let (policy_id, member_id) = (canonical_hex(&policy_id), canonical_hex(&member_id));
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
    let (policy_id, member_id) = (canonical_hex(&policy_id), canonical_hex(&member_id));
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
    headers: HeaderMap,
    Path(policy_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(response) = require_operator(&state, &headers, "admin_list_members") {
        return response;
    }
    let policy_id = canonical_hex(&policy_id);
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
    headers: HeaderMap,
    Path(policy_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(response) = require_operator(&state, &headers, "admin_list_epochs") {
        return response;
    }
    let policy_id = canonical_hex(&policy_id);
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
/// In ZK privacy mode, this uses submitted proofs from the `proof_submissions` table
/// to determine each member's solvency. Members without a submitted proof are
/// marked as insolvent (status=0).
///
/// Pipeline:
/// 1. Fetch eligible members
/// 2. Read proof submissions for the epoch
/// 3. Build Merkle tree
/// 4. Record epoch in DB
/// 5. Update member statuses
async fn admin_trigger_epoch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(response) = require_operator(&state, &headers, "admin_trigger_epoch") {
        return response;
    }
    let policy_id = canonical_hex(&policy_id);
    let rpc = match &state.rpc_fetcher {
        Some(r) => r,
        None => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "RPC not configured"})),
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

    // 2. Determine epoch, fetch members and proof submissions
    let (epoch, leaf_inputs, balance_updates) = {
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

        let eligible: Vec<_> = members.iter()
            .filter(|m| m.effective_epoch <= epoch)
            .collect();

        if eligible.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("No eligible members at epoch {}", epoch)})),
            );
        }

        // Get proof submissions for this epoch
        let submissions = match db.get_proof_submissions_for_epoch(&policy_id, epoch) {
            Ok(s) => s,
            Err(e) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("DB error: {}", e)})),
            ),
        };

        let submission_map: std::collections::HashMap<String, &zk_pof_agent::db::ProofSubmissionRow> =
            submissions.iter().map(|s| (s.member_id.clone(), s)).collect();

        let mut leaf_inputs: Vec<LeafInput> = Vec::new();
        let mut balance_updates: Vec<(String, String, bool)> = Vec::new();

        for member in &eligible {
            let (is_solvent, balance_str) = if let Some(sub) = submission_map.get(&member.member_id) {
                (sub.is_solvent, sub.balance_wei.clone())
            } else {
                // No proof submitted → use last known balance from DB
                let balance: u128 = member.last_balance_wei.parse().unwrap_or(0);
                let threshold: u128 = 1_000_000_000_000_000_000; // 1 ETH
                (balance >= threshold, member.last_balance_wei.clone())
            };

            let status: u8 = if is_solvent { 1 } else { 0 };

            let mut member_id = [0u8; 32];
            if let Ok(bytes) = hex::decode(&member.member_id) {
                if bytes.len() == 32 {
                    member_id.copy_from_slice(&bytes);
                }
            }

            leaf_inputs.push(LeafInput {
                member_id,
                status,
                member_id_hex: member.member_id.clone(),
            });

            balance_updates.push((member.member_id.clone(), balance_str, is_solvent));
        }

        (epoch, leaf_inputs, balance_updates)
    };

    // 3. Parse policy_id bytes
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

    // 4. Build Merkle tree
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

    // 5. Record epoch in DB (no on-chain publication — SP1 proof deferred)
    if let Some(ref publisher) = state.publisher {
        match publisher.record_epoch_only(
            &policy_id,
            epoch,
            block_number,
            &tree_result.root,
            tree_result.member_count,
            None,
        ) {
            Ok(_) => {}
            Err(e) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("DB record failed: {}", e)})),
            ),
        }
    }

    // 6. Update member statuses in DB
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
        "Epoch triggered successfully (ZK mode)"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "epoch": epoch,
            "block_number": block_number,
            "root": format!("0x{}", hex::encode(tree_result.root)),
            "member_count": tree_result.member_count,
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

// ─── Privacy V2 Handlers ────────────────────────────────────────────────────

/// Canonicalize a hex path parameter: drop an optional `0x` prefix, lowercase.
///
/// IDs are stored as lowercase unprefixed hex, but callers legitimately send
/// either form — the V2 routes already accept both via `parse_policy_id`.
/// Without this, a `0x`-prefixed ID matches no row and the handler returns an
/// empty result, which reads as "no such member" rather than "wrong format".
fn canonical_hex(value: &str) -> String {
    value.strip_prefix("0x").unwrap_or(value).to_lowercase()
}

/// Decode a fixed-length hex field (0x prefix optional).
fn decode_hex_array<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    let clean = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(clean).map_err(|e| format!("Invalid hex in {field}: {e}"))?;
    if bytes.len() != N {
        return Err(format!(
            "Invalid {field} length: expected {N} bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// POST /v2/enroll — enroll with a deterministic nullifier + DLEQ proof.
///
/// memberId = SHA256(nullifier), which is cryptographically unique per
/// (key, policy) — unlike the legacy SHA256(signature) identifier, a wallet
/// cannot mint multiple identities for one policy. The public key is used
/// transiently for DLEQ verification and the balance gate; no address is
/// stored.
async fn enroll_v2_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollV2Request>,
) -> (StatusCode, Json<serde_json::Value>) {
    // 1. Decode and canonicalize inputs.
    let policy_id_bytes = match parse_policy_id(&req.policy_id) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid policy_id: {}", e)})),
            );
        }
    };
    let policy_id_hex = hex::encode(policy_id_bytes);

    let parsed = (|| -> Result<([u8; 33], [u8; 33], zk_pof_common::plume::DleqProof), String> {
        let public_key = decode_hex_array::<33>("public_key", &req.public_key)?;
        let nullifier = decode_hex_array::<33>("nullifier", &req.nullifier)?;
        let proof = zk_pof_common::plume::DleqProof {
            a: decode_hex_array::<33>("dleq_a", &req.dleq_a)?,
            b: decode_hex_array::<33>("dleq_b", &req.dleq_b)?,
            s: decode_hex_array::<32>("dleq_s", &req.dleq_s)?,
        };
        Ok((public_key, nullifier, proof))
    })();
    let (public_key, nullifier, proof) = match parsed {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e})));
        }
    };

    // 2. Balance gate when RPC is configured. The address is derived
    //    transiently from the public key and discarded — never stored.
    if let Some(rpc) = &state.rpc_fetcher {
        let address = match zk_pof_common::plume::derive_address(&public_key) {
            Ok(a) => a,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("Invalid public key: {}", e)})),
                );
            }
        };
        let address_hex = format!("0x{}", hex::encode(address));
        let threshold_wei: u128 = 1_000_000_000_000_000_000; // 1 ETH (TODO: read from policy)

        match rpc.get_balance(&address_hex).await {
            Ok(balance) if balance < threshold_wei => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("Insufficient balance: {} < threshold {}", balance, threshold_wei)
                    })),
                );
            }
            Ok(_) => {}
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("Failed to fetch balance: {}", e)})),
                );
            }
        }
    }

    // 3. Verify + register (DB lock only after all awaits).
    let db = state.db.lock().unwrap();
    let current_epoch = db
        .get_latest_epoch(&policy_id_hex)
        .ok()
        .flatten()
        .map(|e| e.epoch)
        .unwrap_or(0);

    let scope_hash = match &req.scope_hash {
        Some(hex_str) => match decode_hex_array::<32>("scope_hash", hex_str) {
            Ok(s) => Some(s),
            Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))),
        },
        None => None,
    };

    let enrollment = NullifierEnrollment {
        policy_id_hex: &policy_id_hex,
        scope_hash,
        public_key,
        nullifier,
        proof,
    };
    match register_nullifier_member(&db, &enrollment, current_epoch) {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "member_id": hex::encode(result.member_id),
                "status": "enrolled",
                "effective_epoch": result.effective_epoch,
                "mode": "nullifier"
            })),
        ),
        Err(e) if e.to_string().contains("already") => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": format!("{}", e)})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{}", e)})),
        ),
    }
}

/// GET /v2/solvent_set/:policy_id — latest solvent-set root metadata.
async fn get_solvent_set_handler(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let policy_id_hex = match parse_policy_id(&policy_id) {
        Ok(p) => hex::encode(p),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid policy_id: {}", e)})),
            );
        }
    };

    let db = state.db.lock().unwrap();
    let service = SolventSetService::new(&db);
    match service.get(&policy_id_hex, None) {
        Ok(Some(row)) => {
            // Snapshot manifest: a published root is useless to members if
            // nobody serves the leaves. Committing to the exact snapshot bytes
            // lets a client verify what it downloaded, and lets mirrors serve
            // it without being trusted (review §4.4).
            let manifest = {
                use sha2::{Digest, Sha256};
                let snapshot = row.addresses_json.as_bytes();
                let mut hasher = Sha256::new();
                hasher.update(snapshot);
                serde_json::json!({
                    "schema": "zkpof-solvent-set-snapshot-v1",
                    // Hash of the canonical stored entry list — the same bytes
                    // /leaves paginates over.
                    "content_sha256": format!("0x{}", hex::encode(hasher.finalize())),
                    "size_bytes": snapshot.len(),
                    "entry_count": row.member_count,
                    "mirrors": snapshot_mirrors(&policy_id_hex, row.epoch),
                })
            };

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "policy_id": row.policy_id,
                    "epoch": row.epoch,
                    "block_number": row.block_number,
                    "root": format!("0x{}", row.root),
                    "member_count": row.member_count,
                    "snapshot": manifest,
                })),
            )
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "No solvent set built for this policy"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Database error: {}", e)})),
        ),
    }
}

/// GET /v2/solvent_set/:policy_id/leaves — the public address list, paginated.
///
/// Serving the *entire* set to any caller is what keeps lookups oblivious:
/// clients download it and compute their own Merkle path locally. There is
/// deliberately no "path for address X" endpoint — that query would reveal X.
async fn get_solvent_set_leaves_handler(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
    Query(query): Query<SolventSetLeavesQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let policy_id_hex = match parse_policy_id(&policy_id) {
        Ok(p) => hex::encode(p),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid policy_id: {}", e)})),
            );
        }
    };

    let db = state.db.lock().unwrap();
    let service = SolventSetService::new(&db);
    let row = match service.get(&policy_id_hex, query.epoch) {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "No solvent set found"})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Database error: {}", e)})),
            );
        }
    };

    let entries = match SolventSetService::decode_entries(&row) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("{}", e)})),
            );
        }
    };

    let total = entries.len();
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(1000).min(10_000);
    let page: Vec<_> = entries.into_iter().skip(offset).take(limit).collect();
    let addresses: Vec<String> = page.iter().map(|e| hex::encode(e.address)).collect();
    let entries_json: Vec<serde_json::Value> = page
        .iter()
        .map(|e| serde_json::json!([hex::encode(e.address), e.streak]))
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "policy_id": row.policy_id,
            "epoch": row.epoch,
            "block_number": row.block_number,
            "root": format!("0x{}", row.root),
            "total": total,
            "offset": offset,
            "limit": limit,
            "addresses": addresses,
            "entries": entries_json
        })),
    )
}

/// POST /v2/admin/build_solvent_set/:policy_id — build the next-epoch solvent set.
///
/// Candidates = explicit list ∪ (optional) Transfer-log discovery; each
/// candidate's balance is sampled at the reference block and addresses at or
/// above the threshold form the set. The set contains *all* qualifying
/// addresses, member or not — the agent never learns who the members are.
async fn admin_build_solvent_set_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
    Json(req): Json<BuildSolventSetRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    use std::collections::BTreeSet;

    if let Err(response) = require_operator(&state, &headers, "build_solvent_set") {
        return response;
    }

    let policy_bytes = match parse_policy_id(&policy_id) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid policy_id: {}", e)})),
            );
        }
    };
    let policy_id_hex = hex::encode(policy_bytes);

    let rpc = match &state.rpc_fetcher {
        Some(r) => r,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "RPC not configured"})),
            );
        }
    };

    // ── Policy parameters: the chain decides, not the request body ──────
    //
    // These used to come straight from the request, defaulting to a
    // hard-coded 1 ETH. An operator could therefore build a set against terms
    // that had nothing to do with what the relying contract checks (review
    // finding R8). The registry is authoritative; anything the caller sends is
    // cross-checked against it and a disagreement is a hard error rather than
    // a silent override.
    let on_chain_policy = match &state.policy_reader {
        Some(reader) => match reader.fetch(&policy_bytes).await {
            Ok(p) => Some(p),
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": format!("Could not read the on-chain policy: {}", e),
                        "hint": "Build parameters are taken from the registry. Fix the \
                                 RPC/registry configuration, or unset \
                                 POLICY_REGISTRY_ADDRESS to run in unpinned dev mode."
                    })),
                );
            }
        },
        None => None,
    };

    let requested_threshold: Option<u128> = match &req.threshold_wei {
        Some(t) => match t.parse() {
            Ok(v) => Some(v),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("Invalid threshold_wei: {}", e)})),
                );
            }
        },
        None => None,
    };

    let requested_token: Option<[u8; 20]> = match &req.token_address {
        Some(t) => match parse_address_bytes(t) {
            Ok(a) => Some(a),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("Invalid token_address: {}", e)})),
                );
            }
        },
        None => None,
    };

    let (threshold_wei, effective_slot) = match &on_chain_policy {
        Some(policy) => {
            if let Err(e) = zk_pof_agent::policy_reader::reject_param_drift(
                policy,
                requested_threshold,
                requested_token.as_ref(),
                req.balance_slot,
            ) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("{}", e)})),
                );
            }
            if !policy.active {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Policy is not active on-chain"})),
                );
            }
            (policy.threshold_wei, policy.balance_slot)
        }
        None => {
            // Unpinned dev mode: no registry configured. Requiring an explicit
            // threshold is better than silently assuming 1 ETH.
            match requested_threshold {
                Some(t) => (t, req.balance_slot.unwrap_or(0)),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "No on-chain policy configured and no threshold_wei given",
                            "hint": "Set POLICY_REGISTRY_ADDRESS + SOLVENT_SET_ORACLE_ADDRESS \
                                     so parameters come from the chain, or pass threshold_wei \
                                     explicitly for a dev build."
                        })),
                    );
                }
            }
        }
    };

    // ── Reference block: sampled, not chosen ────────────────────────────
    //
    // Letting the operator name the block is exactly the lever that makes a
    // "streak" cheap to fake — pick the block you were funded at, every time.
    // The block is therefore derived from chain entropy the operator does not
    // control. The explicit override survives only behind ZKPOF_DEV_ALLOW_
    // BLOCK_OVERRIDE, and never for proven builds.
    let dev_block_override = std::env::var("ZKPOF_DEV_ALLOW_BLOCK_OVERRIDE").as_deref() == Ok("1");
    if req.block_number.is_some() && (!dev_block_override || req.proven) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": if req.proven {
                    "block_number cannot be supplied for a proven build: the reference \
                     block must be sampled from chain entropy, not chosen"
                } else {
                    "block_number override is disabled. Set \
                     ZKPOF_DEV_ALLOW_BLOCK_OVERRIDE=1 for local dev seeding."
                }
            })),
        );
    }

    let block_number = match req.block_number {
        Some(b) => b, // dev-only, non-proven, explicitly enabled above
        None => {
            let latest = match rpc.get_block_number().await {
                Ok(b) => b,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("Failed to fetch block number: {}", e)})),
                    );
                }
            };
            match rpc.get_block_hash(latest).await {
                Ok(entropy) => zk_pof_agent::solvent_set_service::select_reference_block(
                    latest, &entropy, 256,
                ),
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("Failed to fetch block hash: {}", e)})),
                    );
                }
            }
        }
    };

    // Candidate union: explicit + optional Transfer-log discovery.
    let mut candidates: BTreeSet<String> = req
        .candidates
        .iter()
        .map(|c| c.strip_prefix("0x").unwrap_or(c).to_lowercase())
        .collect();

    if let (Some(token), Some(from), Some(to)) =
        (&req.token_address, req.discover_from_block, req.discover_to_block)
    {
        match rpc.get_transfer_logs(token, from, to).await {
            Ok(logs) => {
                for participant in zk_pof_agent::rpc_fetcher::parse_transfer_participants(&logs) {
                    candidates.insert(participant);
                }
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("Transfer-log discovery failed: {}", e)})),
                );
            }
        }
    }
    let candidates: Vec<String> = candidates.into_iter().collect();

    // ── Stage B: EIP-1186-proven build (native ETH or ERC-20) ───────────
    if req.proven {
        // The asset a proven build is derived against comes from the chain
        // whenever a registry is configured: the oracle checks the proof's
        // token and slot against the pinned values, so building from anything
        // else would only produce an unpublishable root.
        let (effective_token, effective_balance_slot) = match &on_chain_policy {
            Some(policy) => (policy.token_address, policy.balance_slot),
            None => (requested_token, effective_slot),
        };

        let token_config = match effective_token {
            Some(address) => {
                if effective_balance_slot == 0 && on_chain_policy.is_none() {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "ERC-20 proven mode requires balance_slot (the balanceOf mapping slot)"
                        })),
                    );
                }
                Some(zk_pof_common::solvent_derivation::TokenConfig {
                    address,
                    balance_slot: effective_balance_slot,
                })
            }
            None => None,
        };

        let chain_id = match rpc.get_chain_id().await {
            Ok(c) => c,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Failed to fetch chain id: {}", e)})),
                );
            }
        };
        // All RPC awaits happen before the DB lock.
        let fetched = match &token_config {
            None => zk_pof_agent::solvent_set_service::fetch_candidate_proofs(
                rpc, &candidates, block_number,
            )
            .await
            .map(|(state_root, proofs)| (state_root, Vec::new(), proofs)),
            Some(config) => zk_pof_agent::solvent_set_service::fetch_erc20_candidate_proofs(
                rpc, config, &candidates, block_number,
            )
            .await,
        };
        let (state_root, token_account_proof, proofs) = match fetched {
            Ok(triple) => triple,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("{}", e)})),
                );
            }
        };

        let db = state.db.lock().unwrap();
        let service = SolventSetService::new(&db);
        let epoch = match service.next_epoch(&policy_id_hex) {
            Ok(e) => e,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Database error: {}", e)})),
                );
            }
        };
        return match service.build_proven_from_proofs(
            &policy_id_hex, epoch, block_number, chain_id, threshold_wei, &state_root, proofs,
            token_config.as_ref(), token_account_proof,
        ) {
            Ok(proven) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "policy_id": proven.result.policy_id,
                    "epoch": proven.result.epoch,
                    "block_number": proven.result.block_number,
                    "root": format!("0x{}", hex::encode(proven.result.root)),
                    "member_count": proven.result.member_count,
                    "candidate_count": proven.public_values.candidate_count,
                    "proven": true,
                    "state_root": format!("0x{}", hex::encode(proven.public_values.state_root)),
                    "prev_root": format!("0x{}", hex::encode(proven.public_values.prev_root)),
                    "note": "Derivation validated natively; generate the on-chain proof with `zkpof-client` / derivation_prover using the same inputs."
                })),
            ),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("{}", e)})),
            ),
        };
    }

    // ── Stage A: balance-checked build (operator-trusted) ───────────────
    // Fetch all balances before touching the DB (no lock across awaits).
    // An RPC failure is NOT evidence of insolvency. Previously a failed fetch
    // silently dropped the candidate, so an RPC outage was indistinguishable
    // from "this address didn't qualify" — and gave an operator deniable
    // censorship (review finding R8). Unresolved candidates are reported, and
    // the build aborts outright when the caller asked for a strict set.
    let mut balances: Vec<(String, u128)> = Vec::with_capacity(candidates.len());
    let mut unresolved: Vec<serde_json::Value> = Vec::new();
    for candidate in &candidates {
        let fetched = match &req.token_address {
            Some(token) => rpc.get_erc20_balance_at_block(token, candidate, block_number).await,
            None => rpc.get_balance_at_block(candidate, block_number).await,
        };
        match fetched {
            Ok(balance) => balances.push((candidate.clone(), balance)),
            Err(e) => {
                tracing::warn!(address = %candidate, error = %e, "Balance fetch failed");
                unresolved.push(serde_json::json!({
                    "address": candidate,
                    "error": format!("{}", e),
                }));
            }
        }
    }

    if !unresolved.is_empty() && req.strict.unwrap_or(true) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!(
                    "{} candidate(s) could not be resolved at block {}; refusing to \
                     publish a set that would silently omit them",
                    unresolved.len(),
                    block_number
                ),
                "unresolved": unresolved,
                "hint": "Retry when the RPC recovers, or pass strict=false to \
                         publish an explicitly-partial set"
            })),
        );
    }

    let db = state.db.lock().unwrap();
    let service = SolventSetService::new(&db);
    let epoch = match service.next_epoch(&policy_id_hex) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Database error: {}", e)})),
            );
        }
    };

    match service.build_from_balances(&policy_id_hex, epoch, block_number, threshold_wei, &balances) {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "policy_id": result.policy_id,
                "epoch": result.epoch,
                "block_number": result.block_number,
                "root": format!("0x{}", hex::encode(result.root)),
                "member_count": result.member_count,
                "candidate_count": candidates.len(),
                "provenance": "operator_asserted",
                // Always reported, never implied: this set covers the
                // candidates supplied and resolved, not "every qualifying
                // address" (review §4.2).
                "resolved_candidate_count": balances.len(),
                "unresolved": unresolved,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{}", e)})),
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
        .route("/submit_proof/:policy_id/:member_id", post(submit_proof_handler))
        .route("/proof/:policy_id/:member_id", get(get_proof))
        .route("/status/:policy_id/:member_id", get(get_status))
        // Privacy V2 endpoints (PRIVACY_V2.md)
        .route("/v2/enroll", post(enroll_v2_handler))
        .route("/v2/solvent_set/:policy_id", get(get_solvent_set_handler))
        .route("/v2/solvent_set/:policy_id/leaves", get(get_solvent_set_leaves_handler))
        .route("/v2/admin/build_solvent_set/:policy_id", post(admin_build_solvent_set_handler))
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

    // Operator control plane: refuse to serve admin routes unauthenticated
    // unless that is an explicit, acknowledged choice. These endpoints build
    // and publish the sets relying protocols trust.
    let admin_token = match std::env::var("ZKPOF_ADMIN_TOKEN") {
        Ok(token) if !token.trim().is_empty() => {
            info!("Operator control plane authenticated via ZKPOF_ADMIN_TOKEN");
            Some(token)
        }
        _ => {
            if std::env::var("ZKPOF_DEV_INSECURE_ADMIN").as_deref() == Ok("1") {
                tracing::warn!(
                    "ZKPOF_ADMIN_TOKEN is unset and ZKPOF_DEV_INSECURE_ADMIN=1 — \
                     operator endpoints are UNAUTHENTICATED. Never do this outside \
                     local development."
                );
                None
            } else {
                panic!(
                    "ZKPOF_ADMIN_TOKEN must be set: /admin/* and /v2/admin/* can \
                     trigger epochs and reshape published sets. Set the variable, \
                     or set ZKPOF_DEV_INSECURE_ADMIN=1 to run without it locally."
                );
            }
        }
    };

    let policy_reader = zk_pof_agent::policy_reader::PolicyReader::from_env();
    if policy_reader.is_some() {
        info!("Build parameters will be read from the on-chain PolicyRegistry");
    } else {
        tracing::warn!(
            "POLICY_REGISTRY_ADDRESS / SOLVENT_SET_ORACLE_ADDRESS unset — builds run in \
             unpinned dev mode and must state their own threshold"
        );
    }

    let state = Arc::new(AppState {
        db: Mutex::new(Database::open(&db_path).expect("Failed to reopen database")),
        rpc_url,
        rpc_fetcher,
        proof_worker,
        publisher,
        admin_token,
        policy_reader,
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
