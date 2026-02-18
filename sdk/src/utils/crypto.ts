import { fromHex, toHex, stripHexPrefix } from "./formatting";

/**
 * Compute a privacy-preserving member ID from a signature.
 * memberId = SHA-256(signature_bytes)
 *
 * @param signature Hex-encoded 65-byte ECDSA signature (with or without 0x prefix).
 * @returns Hex-encoded 32-byte member ID.
 */
export async function computeMemberId(signature: string): Promise<string> {
  const sigBytes = fromHex(stripHexPrefix(signature));
  // Copy into a fresh ArrayBuffer to satisfy crypto.subtle.digest types
  const buf = new ArrayBuffer(sigBytes.length);
  new Uint8Array(buf).set(sigBytes);
  const hashBuffer = await crypto.subtle.digest("SHA-256", buf);
  return toHex(new Uint8Array(hashBuffer));
}

/**
 * Build the enrollment message that the user must sign.
 *
 * Format: "zkpof-holder-v1:{scope}:{nonce}"
 *
 * @param scope The policy scope string (e.g., "defi-protocol-xyz").
 * @param nonce A unique nonce for this enrollment.
 * @returns The message string to sign.
 */
export function buildEnrollmentMessage(scope: string, nonce: string): string {
  return `zkpof-holder-v1:${scope}:${nonce}`;
}

/**
 * Verify that a signature has valid format (65 bytes hex).
 *
 * @param signature Hex-encoded signature.
 * @returns True if format is valid.
 */
export function verifySignatureFormat(signature: string): boolean {
  const clean = stripHexPrefix(signature);
  return /^[0-9a-fA-F]{130}$/.test(clean);
}
