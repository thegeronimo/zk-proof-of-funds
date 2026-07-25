/**
 * Wallet-side PLUME deterministic nullifiers (Privacy V2, PRIVACY_V2.md §3).
 *
 * A JavaScript port of `crates/common/src/plume.rs`, byte-for-byte compatible
 * (locked by shared test vectors in plume.test.ts). This is the crypto a
 * wallet, MetaMask snap, or any raw-key signer context needs to produce V2
 * enrollments — the secret key never leaves the caller's environment.
 *
 * Shipped as a separate subpath (`@zk-proof-of-funds/sdk/plume`) so the core
 * SDK stays dependency-free; this module uses the audited `@noble/curves` and
 * `@noble/hashes` libraries.
 *
 * ```text
 * scope = SHA256("zkpof-scope-v1:" || policy_id)      (default; may be shared)
 * h     = hash_to_curve(scope || sec1(pk), DST)       (ERC-7524 construction)
 * N     = h * sk
 * memberId = SHA256(sec1(N))
 * DLEQ: r = reduce(SHA256("zkpof-dleq-nonce-v1" || sk || pk || N || scope)), A = g*r, B = h*r,
 *       c = reduce(SHA256("zkpof-dleq-chal-v1" || pk || N || A || B || scope)), s = r + c*sk
 * ```
 *
 * The nullifier matches ERC-7524 exactly, so a wallet implementing
 * `eth_getPlumeSignature` yields the same member identity.
 */

import { secp256k1, hashToCurve } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";
import { fromHex, toHex, stripHexPrefix } from "./utils/formatting";

/**
 * RFC 9380 suite, per ERC-7524 — the *standard* secp256k1 DST, so this
 * nullifier is byte-identical to a wallet-produced PLUME nullifier over the
 * same 32-byte message.
 */
export const DST_H2C = "secp256k1_XMD:SHA-256_SSWU_RO_";

/** Prefix used to derive a policy's default scope hash. */
export const SCOPE_PREFIX = "zkpof-scope-v1:";

const DLEQ_NONCE_DOMAIN = new TextEncoder().encode("zkpof-dleq-nonce-v1");
const DLEQ_CHALLENGE_DOMAIN = new TextEncoder().encode("zkpof-dleq-chal-v1");

const Point = secp256k1.ProjectivePoint;
const ORDER = secp256k1.CURVE.n;

/** A Chaum-Pedersen DLEQ proof that `log_g(pk) = log_h(N)` (hex-encoded). */
export interface DleqProof {
  /** Commitment A = g*r (33-byte compressed point, hex). */
  a: string;
  /** Commitment B = h*r (33-byte compressed point, hex). */
  b: string;
  /** Response s = r + c*sk mod n (32 bytes, hex). */
  s: string;
}

/** Everything a V2 enrollment needs, computed locally from the secret key. */
export interface NullifierBundle {
  /** Compressed public key (hex, 33 bytes). */
  publicKey: string;
  /** Compressed nullifier point (hex, 33 bytes). */
  nullifier: string;
  /** memberId = SHA256(nullifier) (hex, 32 bytes). */
  memberId: string;
  /** DLEQ well-formedness proof. */
  dleq: DleqProof;
}

// ── Internals ───────────────────────────────────────────────────────────────

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let x = 0n;
  for (const byte of bytes) x = (x << 8n) | BigInt(byte);
  return x;
}

function bigIntTo32(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function parseSecretKey(skHex: string): bigint {
  const bytes = fromHex(stripHexPrefix(skHex));
  if (bytes.length !== 32) {
    throw new Error(`Invalid secret key length: expected 32 bytes, got ${bytes.length}`);
  }
  const sk = bytesToBigInt(bytes);
  if (sk === 0n || sk >= ORDER) {
    throw new Error("Secret key is not a canonical nonzero scalar");
  }
  return sk;
}

function parsePolicyId(policyIdHex: string): Uint8Array {
  const bytes = fromHex(stripHexPrefix(policyIdHex));
  if (bytes.length !== 32) {
    throw new Error(`Invalid policy_id length: expected 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

function parseScopeHash(scopeHex: string): Uint8Array {
  const bytes = fromHex(stripHexPrefix(scopeHex));
  if (bytes.length !== 32) {
    throw new Error(`Invalid scope_hash length: expected 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

/**
 * A policy's default scope hash: `SHA256("zkpof-scope-v1:" || policy_id)`.
 *
 * Mirrors `plume::default_scope_hash`. Policies that deliberately share an
 * identity namespace pass an explicit shared scope instead.
 */
export function defaultScopeHash(policyIdHex: string): string {
  const policyId = parsePolicyId(policyIdHex);
  return toHex(sha256(concatBytes(new TextEncoder().encode(SCOPE_PREFIX), policyId)));
}

/** Reduce 32 hash bytes to a scalar mod n (bias ≤ 2⁻¹²⁷, same as Rust). */
function reduceToScalar(bytes: Uint8Array): bigint {
  return bytesToBigInt(bytes) % ORDER;
}

/** ERC-7524 base point: `h = hash_to_curve(scope_hash || sec1(pk), DST)`. */
function hashToBasePoint(pkCompressed: Uint8Array, scopeHash: Uint8Array) {
  const input = concatBytes(scopeHash, pkCompressed);
  const h2c = hashToCurve(input, { DST: DST_H2C });
  // Normalize to the curve's ProjectivePoint type.
  return Point.fromAffine(h2c.toAffine());
}

// ── Public API (mirrors crates/common/src/plume.rs) ─────────────────────────

/** Derive the compressed public key `pk = g * sk` (hex in, hex out). */
export function derivePublicKey(skHex: string): string {
  const sk = parseSecretKey(skHex);
  return toHex(Point.BASE.multiply(sk).toRawBytes(true));
}

/** Derive the Ethereum address from a compressed public key. */
export function deriveAddress(pkHex: string): string {
  const point = Point.fromHex(stripHexPrefix(pkHex));
  const uncompressed = point.toRawBytes(false); // 0x04 || x || y
  return toHex(keccak_256(uncompressed.subarray(1)).subarray(12));
}

/**
 * The state-trie key of an address: `keccak256(address)`.
 *
 * Submit this (as `trie_key`) instead of the plaintext address in
 * `/submit_proof` requests — the address then never transits the agent.
 */
export function computeTrieKey(addressHex: string): string {
  const bytes = fromHex(stripHexPrefix(addressHex));
  if (bytes.length !== 20) {
    throw new Error(`Invalid address length: expected 20 bytes, got ${bytes.length}`);
  }
  return toHex(keccak_256(bytes));
}

/** Compute the deterministic nullifier `N = h * sk` for a (key, policy) pair. */
export function computeNullifier(skHex: string, scopeHex: string): string {
  const sk = parseSecretKey(skHex);
  const scope = parseScopeHash(scopeHex);
  const pk = Point.BASE.multiply(sk).toRawBytes(true);
  const h = hashToBasePoint(pk, scope);
  return toHex(h.multiply(sk).toRawBytes(true));
}

/** memberId = SHA256(compressed nullifier). */
export function nullifierHash(nullifierHex: string): string {
  return toHex(sha256(fromHex(stripHexPrefix(nullifierHex))));
}

/**
 * Compute the nullifier and its DLEQ proof — everything `POST /v2/enroll`
 * needs. Deterministic (hedged nonce), so it is idempotent per (key, policy).
 */
export function proveNullifier(skHex: string, scopeHex: string): NullifierBundle {
  const sk = parseSecretKey(skHex);
  const scope = parseScopeHash(scopeHex);
  const skBytes = fromHex(stripHexPrefix(skHex));

  const pkPoint = Point.BASE.multiply(sk);
  const pk = pkPoint.toRawBytes(true);
  const h = hashToBasePoint(pk, scope);
  const nullifierPoint = h.multiply(sk);
  const nullifier = nullifierPoint.toRawBytes(true);
  const msg = scope;

  // Deterministic nonce: r = reduce(H(domain || sk || pk || N || msg)).
  let r = reduceToScalar(sha256(concatBytes(DLEQ_NONCE_DOMAIN, skBytes, pk, nullifier, msg)));
  if (r === 0n) r = 1n; // probability ~2⁻²⁵⁶; keep the proof well-defined

  const a = Point.BASE.multiply(r).toRawBytes(true);
  const b = h.multiply(r).toRawBytes(true);
  const c = reduceToScalar(
    sha256(concatBytes(DLEQ_CHALLENGE_DOMAIN, pk, nullifier, a, b, msg))
  );
  const s = (r + c * sk) % ORDER;

  return {
    publicKey: toHex(pk),
    nullifier: toHex(nullifier),
    memberId: toHex(sha256(nullifier)),
    dleq: { a: toHex(a), b: toHex(b), s: toHex(bigIntTo32(s)) },
  };
}

/**
 * Verify that `nullifier` is the unique well-formed nullifier for
 * (`pk`, `policy_id`): checks the DLEQ relation `log_g(pk) = log_h(N)`.
 */
export function verifyNullifier(
  pkHex: string,
  nullifierHex: string,
  scopeHex: string,
  dleq: DleqProof
): boolean {
  try {
    const scope = parseScopeHash(scopeHex);
    const pkBytes = fromHex(stripHexPrefix(pkHex));
    const nullifierBytes = fromHex(stripHexPrefix(nullifierHex));
    const aBytes = fromHex(stripHexPrefix(dleq.a));
    const bBytes = fromHex(stripHexPrefix(dleq.b));

    const pkPoint = Point.fromHex(toHex(pkBytes));
    const nullifierPoint = Point.fromHex(toHex(nullifierBytes));
    const aPoint = Point.fromHex(toHex(aBytes));
    const bPoint = Point.fromHex(toHex(bBytes));

    const s = bytesToBigInt(fromHex(stripHexPrefix(dleq.s)));
    if (s >= ORDER) return false; // non-canonical response

    const h = hashToBasePoint(pkBytes, scope);
    const msg = scope;
    const c = reduceToScalar(
      sha256(concatBytes(DLEQ_CHALLENGE_DOMAIN, pkBytes, nullifierBytes, aBytes, bBytes, msg))
    );

    // g*s == A + pk*c  and  h*s == B + N*c (unsafe multiply tolerates c=0/s=0).
    const gs = Point.BASE.multiplyUnsafe(s);
    const lhs1 = aPoint.add(pkPoint.multiplyUnsafe(c));
    if (!gs.equals(lhs1)) return false;

    const hs = h.multiplyUnsafe(s);
    const lhs2 = bPoint.add(nullifierPoint.multiplyUnsafe(c));
    return hs.equals(lhs2);
  } catch {
    return false;
  }
}

/**
 * Build the complete `POST /v2/enroll` request body from a raw secret key —
 * the wallet-side entry point. The key never leaves this function's scope.
 */
export function buildEnrollV2Request(
  skHex: string,
  policyIdHex: string,
  scopeHex?: string
): {
  policy_id: string;
  scope_hash: string;
  public_key: string;
  nullifier: string;
  dleq_a: string;
  dleq_b: string;
  dleq_s: string;
} {
  const policyId = toHex(parsePolicyId(policyIdHex));
  const scope = scopeHex ? toHex(parseScopeHash(scopeHex)) : defaultScopeHash(policyIdHex);
  const bundle = proveNullifier(skHex, scope);
  return {
    policy_id: policyId,
    scope_hash: scope,
    public_key: bundle.publicKey,
    nullifier: bundle.nullifier,
    dleq_a: bundle.dleq.a,
    dleq_b: bundle.dleq.b,
    dleq_s: bundle.dleq.s,
  };
}
