//! PLUME-style verifiably deterministic nullifiers on secp256k1.
//!
//! Replaces the malleable `memberId = SHA256(signature)` identifier with a
//! nullifier that is *cryptographically* unique per (key, policy):
//!
//! ```text
//! msg  = "zkpof-nullifier-v2:" || lowercase_hex(policy_id)
//! h    = hash_to_curve(msg || pk_compressed, DST)     (RFC 9380, XMD:SHA-256 SSWU RO)
//! N    = h * sk                                        (the nullifier point)
//! member_id = SHA256(N_compressed)                     (the "nullifier hash")
//! ```
//!
//! Unlike an ECDSA signature, `N` admits no signer discretion: there is no
//! nonce to vary and no `(r, n-s)` malleability, so one key can present exactly
//! one identity per policy.
//!
//! Well-formedness is proven either inside the SP1 membership program (where
//! `sk` is a private input) or, for the monitored enrollment flow, with a
//! Chaum-Pedersen DLEQ proof that `log_g(pk) = log_h(N)` (see [`DleqProof`]).
//!
//! Parameters here are normative for this project (see PRIVACY_V2.md §3); we do
//! not claim wire compatibility with the PLUME spec's test vectors.

use anyhow::{anyhow, bail, Result};
use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::{Group, PrimeField};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, Secp256k1};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// RFC 9380 domain separation tag for hash-to-curve.
pub const DST_H2C: &[u8] = b"zkpof-v1:secp256k1_XMD:SHA-256_SSWU_RO_";

/// Prefix for the per-policy nullifier base message.
pub const NULLIFIER_MSG_PREFIX: &str = "zkpof-nullifier-v2:";

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

/// The per-policy message the nullifier is bound to:
/// `"zkpof-nullifier-v2:" || lowercase_hex(policy_id)`.
pub fn nullifier_message(policy_id: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(NULLIFIER_MSG_PREFIX.len() + 64);
    msg.extend_from_slice(NULLIFIER_MSG_PREFIX.as_bytes());
    msg.extend_from_slice(hex::encode(policy_id).as_bytes());
    msg
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

/// Hash the nullifier base point for a (public key, policy) pair:
/// `h = hash_to_curve(msg_pol || pk_compressed, DST_H2C)`.
fn hash_to_base_point(pk_compressed: &[u8; 33], policy_id: &[u8; 32]) -> Result<ProjectivePoint> {
    let msg = nullifier_message(policy_id);
    let point = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[&msg, pk_compressed.as_slice()],
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

/// Compute the deterministic nullifier `N = h * sk` for a (key, policy) pair.
pub fn compute_nullifier(sk_bytes: &[u8; 32], policy_id: &[u8; 32]) -> Result<[u8; 33]> {
    let sk = parse_secret_key(sk_bytes)?;
    let pk = compress_point(&(ProjectivePoint::GENERATOR * sk));
    let h = hash_to_base_point(&pk, policy_id)?;
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
    policy_id: &[u8; 32],
) -> Result<([u8; 33], DleqProof)> {
    let sk = parse_secret_key(sk_bytes)?;
    let pk_point = ProjectivePoint::GENERATOR * sk;
    let pk = compress_point(&pk_point);
    let h = hash_to_base_point(&pk, policy_id)?;
    let nullifier_point = h * sk;
    let nullifier = compress_point(&nullifier_point);
    let msg = nullifier_message(policy_id);

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
/// (`pk`, `policy_id`): checks the DLEQ relation `log_g(pk) = log_h(N)`.
pub fn verify_nullifier(
    pk: &[u8; 33],
    nullifier: &[u8; 33],
    policy_id: &[u8; 32],
    proof: &DleqProof,
) -> Result<()> {
    let pk_point = parse_point(pk)?;
    let nullifier_point = parse_point(nullifier)?;
    let a_point = parse_point(&proof.a)?;
    let b_point = parse_point(&proof.b)?;

    let s: Scalar = Option::from(Scalar::from_repr(proof.s.into()))
        .ok_or_else(|| anyhow!("DLEQ response s is not a canonical scalar"))?;

    let h = hash_to_base_point(pk, policy_id)?;
    let msg = nullifier_message(policy_id);
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
    fn test_nullifier_deterministic() {
        let n1 = compute_nullifier(&sk(7), &POLICY_A).unwrap();
        let n2 = compute_nullifier(&sk(7), &POLICY_A).unwrap();
        assert_eq!(n1, n2, "Nullifier must be deterministic");
    }

    #[test]
    fn test_nullifier_differs_per_policy_and_key() {
        let n_a = compute_nullifier(&sk(7), &POLICY_A).unwrap();
        let n_b = compute_nullifier(&sk(7), &POLICY_B).unwrap();
        let n_other = compute_nullifier(&sk(8), &POLICY_A).unwrap();
        assert_ne!(n_a, n_b, "Different policies must give unlinkable nullifiers");
        assert_ne!(n_a, n_other, "Different keys must give different nullifiers");
    }

    #[test]
    fn test_dleq_roundtrip() {
        let (nullifier, proof) = prove_nullifier(&sk(42), &POLICY_A).unwrap();
        assert_eq!(nullifier, compute_nullifier(&sk(42), &POLICY_A).unwrap());
        let pk = derive_public_key(&sk(42)).unwrap();
        verify_nullifier(&pk, &nullifier, &POLICY_A, &proof).unwrap();
    }

    #[test]
    fn test_dleq_rejects_wrong_nullifier() {
        // A nullifier computed by a different key cannot be passed off as ours.
        let (_, proof) = prove_nullifier(&sk(42), &POLICY_A).unwrap();
        let forged = compute_nullifier(&sk(43), &POLICY_A).unwrap();
        let pk = derive_public_key(&sk(42)).unwrap();
        assert!(verify_nullifier(&pk, &forged, &POLICY_A, &proof).is_err());
    }

    #[test]
    fn test_dleq_rejects_wrong_policy() {
        // Binding: a proof for policy A must not verify under policy B.
        let (nullifier, proof) = prove_nullifier(&sk(42), &POLICY_A).unwrap();
        let pk = derive_public_key(&sk(42)).unwrap();
        assert!(verify_nullifier(&pk, &nullifier, &POLICY_B, &proof).is_err());
    }

    #[test]
    fn test_dleq_rejects_wrong_pk() {
        let (nullifier, proof) = prove_nullifier(&sk(42), &POLICY_A).unwrap();
        let other_pk = derive_public_key(&sk(43)).unwrap();
        assert!(verify_nullifier(&other_pk, &nullifier, &POLICY_A, &proof).is_err());
    }

    #[test]
    fn test_dleq_rejects_tampered_proof() {
        let (nullifier, proof) = prove_nullifier(&sk(42), &POLICY_A).unwrap();
        let pk = derive_public_key(&sk(42)).unwrap();

        let mut bad_s = proof.clone();
        bad_s.s[31] ^= 0x01;
        assert!(verify_nullifier(&pk, &nullifier, &POLICY_A, &bad_s).is_err());

        let mut bad_a = proof.clone();
        // Swap commitments — still valid points, but the relation must break.
        std::mem::swap(&mut bad_a.a, &mut bad_a.b);
        assert!(verify_nullifier(&pk, &nullifier, &POLICY_A, &bad_a).is_err());
    }

    #[test]
    fn test_rejects_zero_and_invalid_secret_keys() {
        assert!(compute_nullifier(&[0u8; 32], &POLICY_A).is_err());
        // n (the group order) is non-canonical as a scalar encoding.
        let order: [u8; 32] =
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(compute_nullifier(&order, &POLICY_A).is_err());
    }

    #[test]
    fn test_rejects_invalid_points() {
        let (nullifier, proof) = prove_nullifier(&sk(42), &POLICY_A).unwrap();
        let pk = derive_public_key(&sk(42)).unwrap();

        let mut bad_nullifier = nullifier;
        bad_nullifier[0] = 0x05; // invalid SEC1 tag
        assert!(verify_nullifier(&pk, &bad_nullifier, &POLICY_A, &proof).is_err());
    }

    #[test]
    fn test_member_id_is_nullifier_hash() {
        let n = compute_nullifier(&sk(9), &POLICY_A).unwrap();
        let id1 = nullifier_hash(&n);
        let id2 = nullifier_hash(&n);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_nullifier_message_format() {
        let msg = nullifier_message(&POLICY_A);
        let expected = format!("zkpof-nullifier-v2:{}", "aa".repeat(32));
        assert_eq!(msg, expected.as_bytes());
    }
}
