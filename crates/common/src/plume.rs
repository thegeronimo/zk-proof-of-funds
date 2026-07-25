//! PLUME-style verifiably deterministic nullifiers on secp256k1.
//!
//! Replaces the malleable `memberId = SHA256(signature)` identifier with a
//! nullifier that is *cryptographically* unique per (key, scope):
//!
//! ```text
//! scope_hash = SHA256("zkpof-scope-v1:" || policy_id)   (default; may be shared)
//! h          = hash_to_curve(scope_hash || sec1(pk), DST)  (RFC 9380 XMD:SHA-256 SSWU RO)
//! N          = h * sk                                    (the nullifier point)
//! member_id  = SHA256(sec1(N))                           (the "nullifier hash")
//! ```
//!
//! Unlike an ECDSA signature, `N` admits no signer discretion: there is no
//! nonce to vary and no `(r, n-s)` malleability, so one key can present exactly
//! one identity per scope.
//!
//! **ERC-7524 compatibility**: the nullifier is computed exactly as the ERC
//! specifies — `nullifier = htc(m || sec1(pk))^sk` over a 32-byte message `m`
//! (here the scope hash) with the standard `secp256k1_XMD:SHA-256_SSWU_RO_`
//! suite. A wallet shipping `eth_getPlumeSignature` therefore derives the same
//! member identity, which is what makes wallet-native support possible without
//! ever exposing the raw key (PRIVACY_V2.md §3.3).
//!
//! Well-formedness is proven either inside the SP1 membership program (where
//! `sk` is a private input) or, for the monitored enrollment flow, with a
//! Chaum-Pedersen DLEQ proof that `log_g(pk) = log_h(N)` (see [`DleqProof`]).
//! The DLEQ *challenge encoding* is project-specific and is not claimed to
//! match the ERC's proof format; only the nullifier — the identity-defining
//! value — is wire-compatible.

use anyhow::{anyhow, bail, Result};
use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::{Group, PrimeField};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, Secp256k1};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// RFC 9380 hash-to-curve suite, as specified by ERC-7524 (Appendix J.8.1).
///
/// This is the *standard* secp256k1 DST — not a project-specific one — so our
/// nullifier is byte-identical to an ERC-7524 PLUME nullifier over the same
/// 32-byte message. A wallet implementing `eth_getPlumeSignature` therefore
/// produces exactly the member identity this system expects (§3.3).
pub const DST_H2C: &[u8] = b"secp256k1_XMD:SHA-256_SSWU_RO_";

/// Prefix used to derive a policy's default scope hash.
pub const SCOPE_PREFIX: &str = "zkpof-scope-v1:";

const DLEQ_NONCE_DOMAIN: &[u8] = b"zkpof-dleq-nonce-v1";
const DLEQ_CHALLENGE_DOMAIN: &[u8] = b"zkpof-dleq-chal-v1";

/// A Chaum-Pedersen DLEQ proof that `log_g(pk) = log_h(N)`.
///
/// 98 bytes: two compressed points and one scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DleqProof {
    /// Commitment `A = g * r` (compressed).
    pub a: [u8; 33],
    /// Commitment `B = h * r` (compressed).
    pub b: [u8; 33],
    /// Response `s = r + c * sk (mod n)`.
    pub s: [u8; 32],
}

/// A policy's default scope hash: `SHA256("zkpof-scope-v1:" || policy_id)`.
///
/// Scopes are the unit of identity separation. By default every policy gets
/// its own scope, so nullifiers are unlinkable across policies. Two policies
/// that *want* a shared identity (e.g. a protocol family running one
/// sybil-resistance namespace) configure the same explicit scope hash — see
/// `SolventSetOracle.setScopeHash` and PRIVACY_V2.md §3.1.
pub fn default_scope_hash(policy_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SCOPE_PREFIX.as_bytes());
    hasher.update(policy_id);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Parse a secret key, rejecting zero and non-canonical encodings.
fn parse_secret_key(sk_bytes: &[u8; 32]) -> Result<Scalar> {
    let maybe_scalar = Scalar::from_repr((*sk_bytes).into());
    let scalar: Scalar =
        Option::from(maybe_scalar).ok_or_else(|| anyhow!("Secret key is not a canonical scalar"))?;
    if bool::from(scalar.is_zero()) {
        bail!("Secret key must be nonzero");
    }
    Ok(scalar)
}

/// Parse a compressed SEC1 point, rejecting the identity and invalid encodings.
fn parse_point(bytes: &[u8; 33]) -> Result<ProjectivePoint> {
    let encoded = EncodedPoint::from_bytes(bytes)
        .map_err(|e| anyhow!("Invalid SEC1 point encoding: {e}"))?;
    let affine: AffinePoint = Option::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| anyhow!("Point is not on the curve"))?;
    let point = ProjectivePoint::from(affine);
    if bool::from(point.is_identity()) {
        bail!("Point must not be the identity");
    }
    Ok(point)
}

/// Compress a point to 33 bytes (SEC1).
fn compress_point(point: &ProjectivePoint) -> [u8; 33] {
    let encoded = point.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

/// Reduce 32 bytes of hash output to a scalar mod n.
///
/// Modulo bias is ≤ 2⁻¹²⁷ for secp256k1 and is not exploitable here.
fn reduce_to_scalar(bytes: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<k256::U256>>::reduce_bytes(&(*bytes).into())
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// The ERC-7524 nullifier base point for a (public key, scope) pair:
/// `h = hash_to_curve(scope_hash || sec1(pk), DST_H2C)` — a 65-byte input,
/// exactly as the ERC specifies.
fn hash_to_base_point(pk_compressed: &[u8; 33], scope_hash: &[u8; 32]) -> Result<ProjectivePoint> {
    let point = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[scope_hash.as_slice(), pk_compressed.as_slice()],
        &[DST_H2C],
    )
    .map_err(|e| anyhow!("hash_to_curve failed: {e}"))?;
    Ok(point)
}

/// Derive the compressed public key `pk = g * sk`.
pub fn derive_public_key(sk_bytes: &[u8; 32]) -> Result<[u8; 33]> {
    let sk = parse_secret_key(sk_bytes)?;
    let pk = ProjectivePoint::GENERATOR * sk;
    Ok(compress_point(&pk))
}

/// Derive the Ethereum address from a compressed public key:
/// `keccak256(uncompressed_pk[1..65])[12..32]`.
pub fn derive_address(pk_compressed: &[u8; 33]) -> Result<[u8; 20]> {
    let point = parse_point(pk_compressed)?;
    let uncompressed = point.to_affine().to_encoded_point(false);
    let bytes = uncompressed.as_bytes(); // 0x04 || x || y
    let mut keccak = Keccak::v256();
    let mut digest = [0u8; 32];
    keccak.update(&bytes[1..]);
    keccak.finalize(&mut digest);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..]);
    Ok(addr)
}

/// Compute the deterministic nullifier `N = h * sk` for a (key, scope) pair.
pub fn compute_nullifier(sk_bytes: &[u8; 32], scope_hash: &[u8; 32]) -> Result<[u8; 33]> {
    let sk = parse_secret_key(sk_bytes)?;
    let pk = compress_point(&(ProjectivePoint::GENERATOR * sk));
    let h = hash_to_base_point(&pk, scope_hash)?;
    let nullifier = h * sk;
    Ok(compress_point(&nullifier))
}

/// The nullifier hash — used as the memberId and the on-chain nullifierHash.
pub fn nullifier_hash(nullifier: &[u8; 33]) -> [u8; 32] {
    sha256(&[nullifier])
}

/// Compute the nullifier and a DLEQ proof of its well-formedness.
///
/// The nonce is derived deterministically from the secret (hedged, like
/// RFC 6979 / Ed25519), so proving requires no RNG and is idempotent.
pub fn prove_nullifier(
    sk_bytes: &[u8; 32],
    scope_hash: &[u8; 32],
) -> Result<([u8; 33], DleqProof)> {
    let sk = parse_secret_key(sk_bytes)?;
    let pk_point = ProjectivePoint::GENERATOR * sk;
    let pk = compress_point(&pk_point);
    let h = hash_to_base_point(&pk, scope_hash)?;
    let nullifier_point = h * sk;
    let nullifier = compress_point(&nullifier_point);
    let msg = scope_hash.as_slice();

    // Deterministic nonce: r = reduce(H(domain || sk || pk || N || msg))
    let mut r = reduce_to_scalar(&sha256(&[
        DLEQ_NONCE_DOMAIN,
        sk_bytes,
        &pk,
        &nullifier,
        &msg,
    ]));
    if bool::from(r.is_zero()) {
        // Probability ~2⁻²⁵⁶; substitute 1 to keep the proof well-defined.
        r = Scalar::ONE;
    }

    let a = compress_point(&(ProjectivePoint::GENERATOR * r));
    let b = compress_point(&(h * r));
    let c = reduce_to_scalar(&sha256(&[
        DLEQ_CHALLENGE_DOMAIN,
        &pk,
        &nullifier,
        &a,
        &b,
        &msg,
    ]));
    let s = r + c * sk;

    Ok((
        nullifier,
        DleqProof {
            a,
            b,
            s: s.to_bytes().into(),
        },
    ))
}

/// Verify that `nullifier` is the unique well-formed nullifier for
/// (`pk`, `scope_hash`): checks the DLEQ relation `log_g(pk) = log_h(N)`.
pub fn verify_nullifier(
    pk: &[u8; 33],
    nullifier: &[u8; 33],
    scope_hash: &[u8; 32],
    proof: &DleqProof,
) -> Result<()> {
    let pk_point = parse_point(pk)?;
    let nullifier_point = parse_point(nullifier)?;
    let a_point = parse_point(&proof.a)?;
    let b_point = parse_point(&proof.b)?;

    let s: Scalar = Option::from(Scalar::from_repr(proof.s.into()))
        .ok_or_else(|| anyhow!("DLEQ response s is not a canonical scalar"))?;

    let h = hash_to_base_point(pk, scope_hash)?;
    let msg = scope_hash.as_slice();
    let c = reduce_to_scalar(&sha256(&[
        DLEQ_CHALLENGE_DOMAIN,
        pk,
        nullifier,
        &proof.a,
        &proof.b,
        &msg,
    ]));

    // g*s == A + pk*c
    if ProjectivePoint::GENERATOR * s != a_point + pk_point * c {
        bail!("DLEQ verification failed (generator relation)");
    }
    // h*s == B + N*c
    if h * s != b_point + nullifier_point * c {
        bail!("DLEQ verification failed (nullifier relation)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(n: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = n;
        out
    }

    const POLICY_A: [u8; 32] = [0xAA; 32];
    const POLICY_B: [u8; 32] = [0xBB; 32];

    fn scope_a() -> [u8; 32] {
        default_scope_hash(&POLICY_A)
    }
    fn scope_b() -> [u8; 32] {
        default_scope_hash(&POLICY_B)
    }

    #[test]
    fn test_known_addresses() {
        // Canonical test vectors: addresses for private keys 1 and 2.
        let pk1 = derive_public_key(&sk(1)).unwrap();
        assert_eq!(
            hex::encode(derive_address(&pk1).unwrap()),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
        let pk2 = derive_public_key(&sk(2)).unwrap();
        assert_eq!(
            hex::encode(derive_address(&pk2).unwrap()),
            "2b5ad5c4795c026514f8317c7a215e218dccd6cf"
        );
    }

    #[test]
    fn test_default_scope_hash_is_policy_separated() {
        assert_ne!(default_scope_hash(&POLICY_A), default_scope_hash(&POLICY_B));
        assert_eq!(default_scope_hash(&POLICY_A), default_scope_hash(&POLICY_A));
        // Domain-separated from a bare hash of the policy id.
        let bare = sha256(&[&POLICY_A[..]]);
        assert_ne!(default_scope_hash(&POLICY_A), bare);
    }

    #[test]
    fn test_nullifier_deterministic() {
        let n1 = compute_nullifier(&sk(7), &scope_a()).unwrap();
        let n2 = compute_nullifier(&sk(7), &scope_a()).unwrap();
        assert_eq!(n1, n2, "Nullifier must be deterministic");
    }

    #[test]
    fn test_nullifier_differs_per_scope_and_key() {
        let n_a = compute_nullifier(&sk(7), &scope_a()).unwrap();
        let n_b = compute_nullifier(&sk(7), &scope_b()).unwrap();
        let n_other = compute_nullifier(&sk(8), &scope_a()).unwrap();
        assert_ne!(n_a, n_b, "Different scopes must give unlinkable nullifiers");
        assert_ne!(n_a, n_other, "Different keys must give different nullifiers");
    }

    #[test]
    fn test_shared_scope_yields_shared_identity() {
        // Two policies deliberately configured with the SAME scope produce the
        // same member identity — the opt-in cross-policy linkage.
        let shared = [0x5C; 32];
        let from_policy_a_config = compute_nullifier(&sk(7), &shared).unwrap();
        let from_policy_b_config = compute_nullifier(&sk(7), &shared).unwrap();
        assert_eq!(from_policy_a_config, from_policy_b_config);
        assert_ne!(from_policy_a_config, compute_nullifier(&sk(7), &scope_a()).unwrap());
    }

    #[test]
    fn test_dleq_roundtrip() {
        let (nullifier, proof) = prove_nullifier(&sk(42), &scope_a()).unwrap();
        assert_eq!(nullifier, compute_nullifier(&sk(42), &scope_a()).unwrap());
        let pk = derive_public_key(&sk(42)).unwrap();
        verify_nullifier(&pk, &nullifier, &scope_a(), &proof).unwrap();
    }

    #[test]
    fn test_dleq_rejects_wrong_nullifier() {
        // A nullifier computed by a different key cannot be passed off as ours.
        let (_, proof) = prove_nullifier(&sk(42), &scope_a()).unwrap();
        let forged = compute_nullifier(&sk(43), &scope_a()).unwrap();
        let pk = derive_public_key(&sk(42)).unwrap();
        assert!(verify_nullifier(&pk, &forged, &scope_a(), &proof).is_err());
    }

    #[test]
    fn test_dleq_rejects_wrong_scope() {
        // Binding: a proof for scope A must not verify under scope B.
        let (nullifier, proof) = prove_nullifier(&sk(42), &scope_a()).unwrap();
        let pk = derive_public_key(&sk(42)).unwrap();
        assert!(verify_nullifier(&pk, &nullifier, &scope_b(), &proof).is_err());
    }

    #[test]
    fn test_dleq_rejects_wrong_pk() {
        let (nullifier, proof) = prove_nullifier(&sk(42), &scope_a()).unwrap();
        let other_pk = derive_public_key(&sk(43)).unwrap();
        assert!(verify_nullifier(&other_pk, &nullifier, &scope_a(), &proof).is_err());
    }

    #[test]
    fn test_dleq_rejects_tampered_proof() {
        let (nullifier, proof) = prove_nullifier(&sk(42), &scope_a()).unwrap();
        let pk = derive_public_key(&sk(42)).unwrap();

        let mut bad_s = proof.clone();
        bad_s.s[31] ^= 0x01;
        assert!(verify_nullifier(&pk, &nullifier, &scope_a(), &bad_s).is_err());

        let mut bad_a = proof.clone();
        // Swap commitments — still valid points, but the relation must break.
        std::mem::swap(&mut bad_a.a, &mut bad_a.b);
        assert!(verify_nullifier(&pk, &nullifier, &scope_a(), &bad_a).is_err());
    }

    #[test]
    fn test_rejects_zero_and_invalid_secret_keys() {
        assert!(compute_nullifier(&[0u8; 32], &scope_a()).is_err());
        // n (the group order) is non-canonical as a scalar encoding.
        let order: [u8; 32] =
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(compute_nullifier(&order, &scope_a()).is_err());
    }

    #[test]
    fn test_rejects_invalid_points() {
        let (nullifier, proof) = prove_nullifier(&sk(42), &scope_a()).unwrap();
        let pk = derive_public_key(&sk(42)).unwrap();

        let mut bad_nullifier = nullifier;
        bad_nullifier[0] = 0x05; // invalid SEC1 tag
        assert!(verify_nullifier(&pk, &bad_nullifier, &scope_a(), &proof).is_err());
    }

    #[test]
    fn test_member_id_is_nullifier_hash() {
        let n = compute_nullifier(&sk(9), &scope_a()).unwrap();
        let id1 = nullifier_hash(&n);
        let id2 = nullifier_hash(&n);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    /// The nullifier base point must follow ERC-7524 exactly: a 65-byte
    /// hash-to-curve input (32-byte message || 33-byte compressed pk) under
    /// the standard secp256k1 suite. This is what lets a wallet-produced
    /// PLUME nullifier serve as the member identity.
    #[test]
    fn test_erc7524_base_point_construction() {
        assert_eq!(DST_H2C, b"secp256k1_XMD:SHA-256_SSWU_RO_");

        let secret = sk(42);
        let pk = derive_public_key(&secret).unwrap();
        let scope = scope_a();

        // Recompute h independently from the ERC's definition, then N = h^sk.
        let expected_h = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
            &[&scope[..], &pk[..]],
            &[b"secp256k1_XMD:SHA-256_SSWU_RO_"],
        )
        .unwrap();
        let sk_scalar = parse_secret_key(&secret).unwrap();
        let expected_n = compress_point(&(expected_h * sk_scalar));

        assert_eq!(compute_nullifier(&secret, &scope).unwrap(), expected_n);
    }

    /// Emit cross-language test vectors (consumed by sdk/src/plume.test.ts).
    /// Run with: cargo test -p zk-pof-common emit_test_vectors -- --ignored --nocapture
    #[test]
    #[ignore]
    fn emit_test_vectors() {
        for (sk_byte, policy) in [(1u8, POLICY_A), (2, POLICY_A), (42, POLICY_A), (42, POLICY_B)] {
            let secret = sk(sk_byte);
            let scope = default_scope_hash(&policy);
            let pk = derive_public_key(&secret).unwrap();
            let (nullifier, proof) = prove_nullifier(&secret, &scope).unwrap();
            println!("--- sk={sk_byte} policy={}", hex::encode(policy));
            println!("scope_hash: {}", hex::encode(scope));
            println!("pk: {}", hex::encode(pk));
            println!("address: {}", hex::encode(derive_address(&pk).unwrap()));
            println!("nullifier: {}", hex::encode(nullifier));
            println!("member_id: {}", hex::encode(nullifier_hash(&nullifier)));
            println!("dleq_a: {}", hex::encode(proof.a));
            println!("dleq_b: {}", hex::encode(proof.b));
            println!("dleq_s: {}", hex::encode(proof.s));
        }
    }
}
