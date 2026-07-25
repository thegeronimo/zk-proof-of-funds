//! Enrollment — handles member enrollment and signature verification.
//!
//! ## Legacy path (V1, hardened)
//!
//! A member enrolls by signing a deterministic message with their wallet:
//!   Sign("zkpof-holder-v1:{scope}:{nonce}")
//!
//! The agent verifies the signature, checks the initial balance, computes
//! memberId = SHA256(signature), and stores the member for monitoring.
//! High-`s` signatures are rejected (EIP-2), which closes the third-party
//! malleability attack where an observed signature `(r, s, v)` is re-encoded
//! as `(r, n - s, v ^ 1)` to mint a second memberId for the same wallet.
//! Known limitation: the key *owner* can still vary the ECDSA nonce to
//! produce multiple memberIds — only the nullifier path below prevents that.
//!
//! ## Nullifier path (V2, preferred)
//!
//! The member submits a PLUME-style deterministic nullifier plus a DLEQ proof
//! of well-formedness (see `zk_pof_common::plume` and PRIVACY_V2.md §3).
//! memberId = SHA256(nullifier), which is cryptographically unique per
//! (key, policy) — exactly one identity per address per policy.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use zk_pof_common::plume::{self, DleqProof};

use crate::db::Database;
use crate::rpc_fetcher::RpcFetcher;

/// Enrollment service responsible for processing new member enrollments.
pub struct EnrollmentService<'a> {
    db: &'a Database,
    rpc: &'a RpcFetcher,
}

/// Result of a successful enrollment.
#[derive(Debug, Clone)]
pub struct EnrollmentResult {
    pub member_id: [u8; 32],
    pub effective_epoch: u64,
}

impl<'a> EnrollmentService<'a> {
    /// Create a new enrollment service.
    pub fn new(db: &'a Database, rpc: &'a RpcFetcher) -> Self {
        Self { db, rpc }
    }

    /// Process an enrollment request.
    ///
    /// Steps:
    /// 1. Verify ECDSA signature recovers to the claimed wallet address
    /// 2. Check that the wallet has sufficient balance for the policy threshold
    /// 3. Compute memberId = SHA256(signature)
    /// 4. Determine the effective epoch (next epoch after enrollment)
    /// 5. Store the member in the database
    pub async fn enroll(
        &self,
        policy_id_hex: &str,
        wallet_address_hex: &str,
        signature: &[u8],
        signed_message: &str,
        threshold_wei: &str,
        current_epoch: u64,
    ) -> Result<EnrollmentResult> {
        // 1. Verify signature recovers to the claimed address
        let recovered_address = recover_address(signed_message, signature)
            .context("Failed to recover signer address from signature")?;

        let claimed_address = parse_address(wallet_address_hex)
            .context("Invalid wallet address")?;

        if recovered_address != claimed_address {
            bail!(
                "Signature verification failed: recovered 0x{} but claimed 0x{}",
                hex::encode(recovered_address),
                hex::encode(claimed_address)
            );
        }

        // 2. Verify the signed message format: "zkpof-holder-v1:{scope}:{nonce}"
        if !signed_message.starts_with("zkpof-holder-v1:") {
            bail!("Invalid signed message format: must start with 'zkpof-holder-v1:'");
        }

        // 3. Check balance via RPC (trusted mode — simple eth_getBalance)
        let balance_wei = self.rpc
            .get_balance(wallet_address_hex)
            .await
            .context("Failed to fetch wallet balance")?;

        let threshold = threshold_wei.parse::<u128>()
            .context("Invalid threshold_wei")?;

        if balance_wei < threshold {
            bail!(
                "Insufficient balance: {} < threshold {}",
                balance_wei,
                threshold
            );
        }

        // 4. Compute memberId = SHA256(signature)
        let member_id = compute_member_id(signature);
        let member_id_hex = hex::encode(member_id);

        // 5. Check if already enrolled
        if self.db.get_member_for_policy(&member_id_hex, policy_id_hex)?.is_some() {
            bail!("Member {} is already enrolled in policy {}", member_id_hex, policy_id_hex);
        }

        // 6. Determine effective epoch (next epoch after enrollment)
        let effective_epoch = current_epoch + 1;

        // 7. Get current timestamp
        let enrolled_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 8. Store in database (no wallet address stored)
        self.db.insert_member(
            &member_id_hex,
            policy_id_hex,
            enrolled_at,
            effective_epoch,
        )?;

        info!(
            member_id = %member_id_hex,
            policy_id = %policy_id_hex,
            effective_epoch = effective_epoch,
            "Member enrolled successfully"
        );

        Ok(EnrollmentResult {
            member_id,
            effective_epoch,
        })
    }

    /// Process a V2 (nullifier) enrollment for the monitored flow.
    ///
    /// The nullifier's scope comes from `enrollment.scope_hash` (defaulting to
    /// the policy's own scope).
    ///
    /// Verifies the DLEQ proof, checks the wallet's balance against the policy
    /// threshold (the address is derived transiently from the public key and
    /// never stored), and registers `memberId = SHA256(nullifier)`.
    pub async fn enroll_v2(
        &self,
        enrollment: &NullifierEnrollment<'_>,
        threshold_wei: &str,
        current_epoch: u64,
    ) -> Result<EnrollmentResult> {
        // Balance gate first (cheap rejection before any DB writes).
        let address = plume::derive_address(&enrollment.public_key)
            .context("Invalid public key")?;
        let address_hex = format!("0x{}", hex::encode(address));

        let balance_wei = self.rpc
            .get_balance(&address_hex)
            .await
            .context("Failed to fetch wallet balance")?;

        let threshold = threshold_wei.parse::<u128>()
            .context("Invalid threshold_wei")?;

        if balance_wei < threshold {
            bail!(
                "Insufficient balance: {} < threshold {}",
                balance_wei,
                threshold
            );
        }

        register_nullifier_member(self.db, enrollment, current_epoch)
    }
}

// ─── V2: Nullifier enrollment ───────────────────────────────────────────────

/// A V2 enrollment request: a deterministic nullifier plus its DLEQ proof.
#[derive(Debug, Clone)]
pub struct NullifierEnrollment<'a> {
    /// Policy identifier as 32-byte hex (0x prefix optional).
    pub policy_id_hex: &'a str,
    /// Scope the nullifier is bound to. `None` uses the policy's default
    /// scope (`SHA256("zkpof-scope-v1:" || policy_id)`); an explicit value
    /// lets policies share one sybil-resistance namespace.
    pub scope_hash: Option<[u8; 32]>,
    /// Compressed secp256k1 public key of the wallet.
    pub public_key: [u8; 33],
    /// Compressed nullifier point `N = hash_to_curve(msg, pk) * sk`.
    pub nullifier: [u8; 33],
    /// Chaum-Pedersen DLEQ proof that `log_g(pk) = log_h(N)`.
    pub proof: DleqProof,
}

/// Parse and canonicalize a 32-byte policy id from hex.
///
/// V2 flows require real 32-byte policy ids because the nullifier message is
/// bound to the policy bytes (`"zkpof-nullifier-v2:" || hex(policy_id)`).
pub fn parse_policy_id(policy_id_hex: &str) -> Result<[u8; 32]> {
    let clean = policy_id_hex.strip_prefix("0x").unwrap_or(policy_id_hex);
    let bytes = hex::decode(clean).context("Invalid hex in policy_id")?;
    if bytes.len() != 32 {
        bail!("Invalid policy_id length: expected 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Verify a nullifier enrollment and register the member.
///
/// `memberId = SHA256(nullifier)` — deterministic per (key, policy), so a key
/// can hold exactly one identity per policy. Duplicate registrations are
/// rejected via the nullifier table's uniqueness constraint.
///
/// Performs no balance check — callers that gate on solvency (the monitored
/// flow) check the balance first; the pure solvent-set flow (PRIVACY_V2.md §4)
/// does not use enrollment at all.
pub fn register_nullifier_member(
    db: &Database,
    enrollment: &NullifierEnrollment<'_>,
    current_epoch: u64,
) -> Result<EnrollmentResult> {
    let policy_id = parse_policy_id(enrollment.policy_id_hex)?;
    let policy_id_hex = hex::encode(policy_id); // canonical lowercase, no 0x
    let scope_hash = enrollment
        .scope_hash
        .unwrap_or_else(|| plume::default_scope_hash(&policy_id));

    plume::verify_nullifier(
        &enrollment.public_key,
        &enrollment.nullifier,
        &scope_hash,
        &enrollment.proof,
    )
    .context("Nullifier DLEQ verification failed")?;

    let member_id = plume::nullifier_hash(&enrollment.nullifier);
    let member_id_hex = hex::encode(member_id);

    if db.nullifier_exists(&policy_id_hex, &member_id_hex)? {
        bail!(
            "Nullifier already registered for policy {} — one identity per key per policy",
            policy_id_hex
        );
    }
    if db.get_member_for_policy(&member_id_hex, &policy_id_hex)?.is_some() {
        bail!("Member {} is already enrolled in policy {}", member_id_hex, policy_id_hex);
    }

    let effective_epoch = current_epoch + 1;
    let enrolled_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    db.insert_member(&member_id_hex, &policy_id_hex, enrolled_at, effective_epoch)?;
    db.insert_nullifier(&policy_id_hex, &member_id_hex, &hex::encode(enrollment.nullifier))?;

    info!(
        member_id = %member_id_hex,
        policy_id = %policy_id_hex,
        effective_epoch = effective_epoch,
        "Member enrolled via nullifier (V2)"
    );

    Ok(EnrollmentResult {
        member_id,
        effective_epoch,
    })
}

/// Compute memberId = SHA256(signature).
///
/// This is the privacy-preserving identifier used in the Merkle tree.
/// Deterministic — the same signature always produces the same memberId.
pub fn compute_member_id(signature: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(signature);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Recover the Ethereum address from a signed message using EIP-191 personal_sign.
///
/// The message is hashed as:
///   keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
///
/// Then ecrecover is used to get the public key, and the address is the last 20
/// bytes of keccak256(public_key).
pub fn recover_address(message: &str, signature: &[u8]) -> Result<[u8; 20]> {
    use alloy::primitives::{Signature, U256, eip191_hash_message};

    if signature.len() != 65 {
        bail!("Invalid signature length: expected 65, got {}", signature.len());
    }

    // Parse signature: r (32) + s (32) + v (1)
    let r = U256::from_be_slice(&signature[0..32]);
    let s = U256::from_be_slice(&signature[32..64]);
    let v = signature[64];

    // v should be 27 or 28, or 0/1 (some signers use 0/1)
    // v=27 (or 0) → even parity (false), v=28 (or 1) → odd parity (true)
    let y_parity = match v {
        28 | 1 => true,
        27 | 0 => false,
        _ => bail!("Invalid v value in signature: {}", v),
    };

    // EIP-2 low-s enforcement: for any valid (r, s, v), the encoding
    // (r, n - s, v ^ 1) is equally valid for the same key and message.
    // Since memberId = SHA256(signature), accepting both encodings would let
    // anyone who observes a signature mint a second memberId for the same
    // wallet. secp256k1 half-order = (n - 1) / 2.
    let half_n = U256::from_limbs([
        0xDFE92F46681B20A0,
        0x5D576E7357A4501D,
        0xFFFFFFFFFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
    ]);
    if s > half_n {
        bail!("High-s signature rejected (EIP-2 low-s required — malleable encoding)");
    }

    let sig = Signature::new(r, s, y_parity);

    // EIP-191 hash the message
    let message_hash = eip191_hash_message(message.as_bytes());

    // Recover the address
    let recovered = sig.recover_address_from_prehash(&message_hash)
        .context("ecrecover failed")?;

    let mut addr = [0u8; 20];
    addr.copy_from_slice(recovered.as_slice());
    Ok(addr)
}

/// Parse a hex-encoded Ethereum address (with or without 0x prefix).
pub fn parse_address(hex_str: &str) -> Result<[u8; 20]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .context("Invalid hex in address")?;
    if bytes.len() != 20 {
        bail!("Invalid address length: expected 20, got {}", bytes.len());
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_member_id_deterministic() {
        let sig = vec![0xAA; 65];
        let id1 = compute_member_id(&sig);
        let id2 = compute_member_id(&sig);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_member_id_different_sigs() {
        let sig1 = vec![0xAA; 65];
        let sig2 = vec![0xBB; 65];
        let id1 = compute_member_id(&sig1);
        let id2 = compute_member_id(&sig2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_parse_address_with_prefix() {
        let addr = parse_address("0x1234567890abcdef1234567890abcdef12345678").unwrap();
        assert_eq!(hex::encode(addr), "1234567890abcdef1234567890abcdef12345678");
    }

    #[test]
    fn test_parse_address_without_prefix() {
        let addr = parse_address("1234567890abcdef1234567890abcdef12345678").unwrap();
        assert_eq!(hex::encode(addr), "1234567890abcdef1234567890abcdef12345678");
    }

    #[test]
    fn test_parse_address_invalid_length() {
        assert!(parse_address("1234").is_err());
    }

    #[test]
    fn test_parse_address_invalid_hex() {
        assert!(parse_address("0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").is_err());
    }

    // ── Low-s / malleability hardening ──────────────────────────────────

    /// secp256k1 group order n.
    const SECP256K1_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    fn signed_message_fixture() -> (alloy::signers::local::PrivateKeySigner, Vec<u8>, String) {
        use alloy::signers::SignerSync;
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let message = "zkpof-holder-v1:test-scope:42".to_string();
        let sig = signer.sign_message_sync(message.as_bytes()).unwrap();
        (signer, sig.as_bytes().to_vec(), message)
    }

    #[test]
    fn test_recover_address_accepts_low_s() {
        let (signer, sig_bytes, message) = signed_message_fixture();
        let recovered = recover_address(&message, &sig_bytes).unwrap();
        assert_eq!(recovered, signer.address().into_array());
    }

    #[test]
    fn test_recover_address_rejects_malleated_high_s() {
        use alloy::primitives::U256;

        let (_, sig_bytes, message) = signed_message_fixture();

        // Malleate: (r, s, v) → (r, n - s, v ^ 1). This encoding is equally
        // valid ECDSA for the same key/message and, before hardening, produced
        // a second distinct memberId (= SHA256(signature)) for the same wallet.
        let n = U256::from_str_radix(SECP256K1_N, 16).unwrap();
        let s = U256::from_be_slice(&sig_bytes[32..64]);
        let high_s = n - s;

        let mut malleated = sig_bytes.clone();
        malleated[32..64].copy_from_slice(&high_s.to_be_bytes::<32>());
        malleated[64] = match sig_bytes[64] {
            27 => 28,
            28 => 27,
            0 => 1,
            _ => 0,
        };

        let err = recover_address(&message, &malleated).unwrap_err();
        assert!(
            err.to_string().contains("High-s"),
            "Expected high-s rejection, got: {err}"
        );

        // And the two encodings would have produced different memberIds.
        assert_ne!(compute_member_id(&sig_bytes), compute_member_id(&malleated));
    }

    // ── V2: nullifier enrollment ────────────────────────────────────────

    use crate::db::Database;
    use zk_pof_common::plume::{derive_public_key, prove_nullifier};

    const POLICY_HEX: &str = "abababababababababababababababababababababababababababababababab";
    const OTHER_POLICY_HEX: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    fn test_sk(n: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = n;
        out
    }

    fn nullifier_enrollment(sk: &[u8; 32], policy_id_hex: &'static str) -> NullifierEnrollment<'static> {
        let policy_id = parse_policy_id(policy_id_hex).unwrap();
        let scope = zk_pof_common::plume::default_scope_hash(&policy_id);
        let (nullifier, proof) = prove_nullifier(sk, &scope).unwrap();
        NullifierEnrollment {
            policy_id_hex,
            scope_hash: None,
            public_key: derive_public_key(sk).unwrap(),
            nullifier,
            proof,
        }
    }

    /// Enrollment bound to an explicit shared scope.
    fn scoped_enrollment(
        sk: &[u8; 32],
        policy_id_hex: &'static str,
        scope: [u8; 32],
    ) -> NullifierEnrollment<'static> {
        let (nullifier, proof) = prove_nullifier(sk, &scope).unwrap();
        NullifierEnrollment {
            policy_id_hex,
            scope_hash: Some(scope),
            public_key: derive_public_key(sk).unwrap(),
            nullifier,
            proof,
        }
    }

    #[test]
    fn test_parse_policy_id() {
        assert!(parse_policy_id(POLICY_HEX).is_ok());
        assert!(parse_policy_id(&format!("0x{POLICY_HEX}")).is_ok());
        assert!(parse_policy_id("abcd").is_err());
        assert!(parse_policy_id("policy_001").is_err());
    }

    #[test]
    fn test_register_nullifier_member() {
        let db = Database::open_in_memory().unwrap();
        let enrollment = nullifier_enrollment(&test_sk(5), POLICY_HEX);

        let result = register_nullifier_member(&db, &enrollment, 10).unwrap();
        assert_eq!(result.effective_epoch, 11);

        let member_id_hex = hex::encode(result.member_id);
        let member = db.get_member(&member_id_hex).unwrap().unwrap();
        assert_eq!(member.policy_id, POLICY_HEX);
        assert!(db.nullifier_exists(POLICY_HEX, &member_id_hex).unwrap());
    }

    #[test]
    fn test_register_nullifier_rejects_duplicate() {
        let db = Database::open_in_memory().unwrap();
        let enrollment = nullifier_enrollment(&test_sk(5), POLICY_HEX);

        register_nullifier_member(&db, &enrollment, 10).unwrap();
        // The same key cannot mint a second identity for the same policy —
        // its nullifier is deterministic, so re-enrollment is always a dup.
        let err = register_nullifier_member(&db, &enrollment, 11).unwrap_err();
        assert!(err.to_string().contains("already"), "got: {err}");
    }

    #[test]
    fn test_register_nullifier_different_policy_is_new_identity() {
        let db = Database::open_in_memory().unwrap();
        let sk = test_sk(5);

        let r1 = register_nullifier_member(&db, &nullifier_enrollment(&sk, POLICY_HEX), 10).unwrap();
        let r2 =
            register_nullifier_member(&db, &nullifier_enrollment(&sk, OTHER_POLICY_HEX), 10).unwrap();
        assert_ne!(r1.member_id, r2.member_id, "Policies must be unlinkable");
    }

    #[test]
    fn test_shared_scope_gives_one_identity_across_policies() {
        // Two policies configured with the same explicit scope produce the
        // same memberId — the opt-in cross-policy identity.
        let db = Database::open_in_memory().unwrap();
        let sk = test_sk(5);
        let shared = [0x5C; 32];

        let a = register_nullifier_member(&db, &scoped_enrollment(&sk, POLICY_HEX, shared), 10)
            .unwrap();
        let b =
            register_nullifier_member(&db, &scoped_enrollment(&sk, OTHER_POLICY_HEX, shared), 10)
                .unwrap();
        assert_eq!(a.member_id, b.member_id, "Shared scope => shared identity");

        // ...and it differs from the default per-policy scope.
        let db2 = Database::open_in_memory().unwrap();
        let default_id =
            register_nullifier_member(&db2, &nullifier_enrollment(&sk, POLICY_HEX), 10).unwrap();
        assert_ne!(a.member_id, default_id.member_id);
    }

    #[test]
    fn test_register_nullifier_rejects_invalid_proof() {
        let db = Database::open_in_memory().unwrap();
        let mut enrollment = nullifier_enrollment(&test_sk(5), POLICY_HEX);
        enrollment.proof.s[31] ^= 0x01;
        assert!(register_nullifier_member(&db, &enrollment, 10).is_err());
    }

    #[test]
    fn test_register_nullifier_rejects_stolen_nullifier() {
        // An attacker presenting their own pk with someone else's nullifier
        // (and proof) must fail DLEQ verification.
        let db = Database::open_in_memory().unwrap();
        let victim = nullifier_enrollment(&test_sk(5), POLICY_HEX);
        let attacker = NullifierEnrollment {
            policy_id_hex: POLICY_HEX,
            scope_hash: None,
            public_key: derive_public_key(&test_sk(6)).unwrap(),
            nullifier: victim.nullifier,
            proof: victim.proof.clone(),
        };
        assert!(register_nullifier_member(&db, &attacker, 10).is_err());
    }
}
