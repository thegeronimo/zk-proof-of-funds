import { fromHex, toHex } from "./formatting";

/** SHA-256 hash helper that handles TypeScript strict ArrayBuffer typing. */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = new ArrayBuffer(data.length);
  new Uint8Array(buf).set(data);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(hash);
}

/**
 * Compute a Merkle leaf hash matching the on-chain MerkleVerifier.computeLeaf().
 *
 * leaf = SHA-256(memberId || status || epoch_be_bytes || policyId)
 *   - memberId:  32 bytes
 *   - status:    1 byte (0 or 1)
 *   - epoch:     8 bytes (big-endian uint64)
 *   - policyId:  32 bytes
 *
 * @param memberId  Hex-encoded 32-byte member ID.
 * @param status    Status byte (1 = solvent, 0 = insolvent).
 * @param epoch     Epoch number.
 * @param policyId  Hex-encoded 32-byte policy ID.
 * @returns Hex-encoded 32-byte leaf hash.
 */
export async function computeLeaf(
  memberId: string,
  status: number,
  epoch: number,
  policyId: string
): Promise<string> {
  const memberIdBytes = fromHex(memberId);
  const policyIdBytes = fromHex(policyId);

  // 32 + 1 + 8 + 32 = 73 bytes
  const buf = new ArrayBuffer(73);
  const buffer = new Uint8Array(buf);
  buffer.set(memberIdBytes, 0);
  buffer[32] = status;

  // epoch as big-endian uint64
  const epochView = new DataView(buf, 33, 8);
  epochView.setBigUint64(0, BigInt(epoch), false);

  buffer.set(policyIdBytes, 41);

  const hash = await sha256(buffer);
  return toHex(hash);
}

/**
 * Verify a Merkle inclusion proof (client-side).
 *
 * Matches the SHA-256 binary Merkle tree used by the Rust backend and
 * the on-chain MerkleVerifier.verifyProof().
 *
 * @param leaf      Hex-encoded 32-byte leaf hash.
 * @param leafIndex Position of the leaf in the tree (0-based).
 * @param proof     Array of hex-encoded 32-byte sibling hashes.
 * @param root      Hex-encoded 32-byte expected root.
 * @returns True if the proof is valid.
 */
export async function verifyProof(
  leaf: string,
  leafIndex: number,
  proof: string[],
  root: string
): Promise<boolean> {
  let current = fromHex(leaf);
  let index = leafIndex;

  for (const siblingHex of proof) {
    const sibling = fromHex(siblingHex);
    const combined = new Uint8Array(64);

    if (index % 2 === 0) {
      // current is left child
      combined.set(current, 0);
      combined.set(sibling, 32);
    } else {
      // current is right child
      combined.set(sibling, 0);
      combined.set(current, 32);
    }

    current = await sha256(combined);
    index = Math.floor(index / 2);
  }

  return toHex(current) === toHex(fromHex(root));
}
