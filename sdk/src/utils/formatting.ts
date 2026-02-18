/** Strip optional "0x" prefix from a hex string. */
export function stripHexPrefix(hex: string): string {
  return hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
}

/** Ensure a hex string has a "0x" prefix. */
export function ensureHexPrefix(hex: string): string {
  return hex.startsWith("0x") || hex.startsWith("0X") ? hex : `0x${hex}`;
}

/** Convert a Uint8Array to a hex string (no prefix). */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Convert a hex string to a Uint8Array. Accepts optional 0x prefix. */
export function fromHex(hex: string): Uint8Array {
  const clean = stripHexPrefix(hex);
  if (clean.length % 2 !== 0) {
    throw new Error(`Invalid hex string length: ${clean.length}`);
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Validate an Ethereum address (20 bytes hex, with or without 0x prefix). */
export function isValidAddress(address: string): boolean {
  const clean = stripHexPrefix(address);
  return /^[0-9a-fA-F]{40}$/.test(clean);
}

/** Validate a 32-byte hex identifier (policy ID or member ID). */
export function isValidBytes32(id: string): boolean {
  const clean = stripHexPrefix(id);
  return /^[0-9a-fA-F]{64}$/.test(clean);
}

/** Validate a 65-byte hex signature. */
export function isValidSignature(sig: string): boolean {
  const clean = stripHexPrefix(sig);
  return /^[0-9a-fA-F]{130}$/.test(clean);
}
