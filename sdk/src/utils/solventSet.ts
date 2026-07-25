import { fromHex, toHex, stripHexPrefix } from "./formatting";

/**
 * Privacy V2 solvent-set utilities (PRIVACY_V2.md §4, streak-aware).
 *
 * The solvent set is the public list of all (address, streak) entries meeting
 * a policy threshold at a reference block, served by the agent in canonical
 * order (sorted ascending by address, deduplicated). The streak counts
 * consecutive epochs in the set — membership proofs assert `streak >=
 * minStreak`, which makes rented solvency cost as much as real solvency.
 *
 * Clients download the list and compute their own Merkle path locally — never
 * ask a server for "the path for address X"; the query itself would reveal X.
 *
 * All hashing uses Web Crypto — zero external dependencies.
 */

/** One solvent-set entry as served by the agent: [hexAddress, streak]. */
export type SolventSetEntryTuple = [string, number];

/** Domain separation tag for solvent-set leaves (v2: streak-aware). */
const SOLVENT_LEAF_DOMAIN = new TextEncoder().encode("zkpof-solvent-leaf-v2");

/** SHA-256 hash helper that handles TypeScript strict ArrayBuffer typing. */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = new ArrayBuffer(data.length);
  new Uint8Array(buf).set(data);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(hash);
}

async function hashPair(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const combined = new Uint8Array(64);
  combined.set(left, 0);
  combined.set(right, 32);
  return sha256(combined);
}

function parseAddress(address: string): Uint8Array {
  const bytes = fromHex(stripHexPrefix(address));
  if (bytes.length !== 20) {
    throw new Error(`Invalid address length: expected 20 bytes, got ${bytes.length}`);
  }
  return bytes;
}

/** A client-side membership path into the solvent-set tree. */
export interface SolventSetPath {
  /** Position of the address's leaf in the canonical tree. */
  leafIndex: number;
  /** The committed streak for this address (needed by the prover witness). */
  streak: number;
  /** Hex-encoded sibling hashes from leaf to root. */
  siblings: string[];
}

/**
 * Compute a solvent-set leaf:
 * SHA-256("zkpof-solvent-leaf-v2" || address || streak_be4).
 *
 * Matches `crates/common/src/solvent_set.rs::compute_solvent_leaf`.
 *
 * @param address Hex-encoded 20-byte address (0x prefix optional).
 * @param streak  Consecutive epochs in the set (>= 1).
 * @returns Hex-encoded 32-byte leaf hash.
 */
export async function computeSolventLeaf(address: string, streak: number): Promise<string> {
  const addressBytes = parseAddress(address);
  const buffer = new Uint8Array(SOLVENT_LEAF_DOMAIN.length + 20 + 4);
  buffer.set(SOLVENT_LEAF_DOMAIN, 0);
  buffer.set(addressBytes, SOLVENT_LEAF_DOMAIN.length);
  new DataView(buffer.buffer).setUint32(SOLVENT_LEAF_DOMAIN.length + 20, streak, false);
  return toHex(await sha256(buffer));
}

/** Compute all leaves for a served entry list, preserving order. */
async function computeLeaves(entries: SolventSetEntryTuple[]): Promise<Uint8Array[]> {
  const leaves: Uint8Array[] = [];
  for (const [address, streak] of entries) {
    leaves.push(fromHex(await computeSolventLeaf(address, streak)));
  }
  return leaves;
}

/**
 * Compute the solvent-set Merkle root from the served entry list.
 *
 * The list must be in the agent's canonical order — do not re-sort it; leaf
 * indices are defined by that order. Odd levels duplicate the last node,
 * matching the Rust tree and MerkleVerifier.sol. Empty list → zero root.
 *
 * @returns Hex-encoded 32-byte root.
 */
export async function computeSolventSetRoot(entries: SolventSetEntryTuple[]): Promise<string> {
  let level = await computeLeaves(entries);
  if (level.length === 0) {
    return "0".repeat(64);
  }
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(await hashPair(left, right));
    }
    level = next;
  }
  return toHex(level[0]);
}

/**
 * Compute the membership path for an address in the served entry list.
 *
 * Runs entirely client-side. Returns null if the address is not in the set
 * (i.e. it did not meet the threshold at the reference block).
 *
 * @param entries   The full entry list in the agent's canonical order.
 * @param myAddress The caller's address (0x prefix optional, case-insensitive).
 */
export async function computeSolventSetPath(
  entries: SolventSetEntryTuple[],
  myAddress: string
): Promise<SolventSetPath | null> {
  const target = toHex(parseAddress(myAddress));
  const leafIndex = entries.findIndex(
    ([address]) => stripHexPrefix(address).toLowerCase() === target
  );
  if (leafIndex === -1) {
    return null;
  }
  const streak = entries[leafIndex][1];

  const siblings: string[] = [];
  let level = await computeLeaves(entries);
  let index = leafIndex;

  while (level.length > 1) {
    // Pad to even length by duplicating the last element.
    if (level.length % 2 === 1) {
      level.push(level[level.length - 1]);
    }
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    siblings.push(toHex(level[siblingIndex]));

    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(await hashPair(level[i], level[i + 1]));
    }
    level = next;
    index = Math.floor(index / 2);
  }

  return { leafIndex, streak, siblings };
}

/**
 * Verify a solvent-set membership path against a root.
 *
 * @param address   Hex-encoded 20-byte address.
 * @param streak    The committed streak for the address.
 * @param leafIndex Position of the leaf in the tree.
 * @param siblings  Hex-encoded sibling hashes from leaf to root.
 * @param root      Hex-encoded 32-byte expected root.
 */
export async function verifySolventMembership(
  address: string,
  streak: number,
  leafIndex: number,
  siblings: string[],
  root: string
): Promise<boolean> {
  let current = fromHex(await computeSolventLeaf(address, streak));
  let index = leafIndex;

  for (const siblingHex of siblings) {
    const sibling = fromHex(siblingHex);
    current =
      index % 2 === 0 ? await hashPair(current, sibling) : await hashPair(sibling, current);
    index = Math.floor(index / 2);
  }

  return toHex(current) === toHex(fromHex(root));
}
