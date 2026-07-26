/**
 * Decoding and checking Privacy V2 membership public values (PRIVACY_V2.md §4.2).
 *
 * `program-membership/` commits a single 224-byte blob:
 *
 * ```text
 * abi.encode(bytes32 solventSetRoot, bytes32 policyId, uint64 epoch,
 *            bytes32 nullifierHash, uint64 chainId, uint64 minStreak,
 *            bytes32 scopeHash)
 * ```
 *
 * Seven 32-byte words, with the three `uint64`s left-padded — so decoding is
 * fixed-offset slicing and needs no ABI library, keeping the core SDK zero-dep.
 *
 * A relying party must never take these values on faith from whoever handed
 * them over: `checkMembershipPublicValues` re-checks every field against what
 * the caller independently knows (the root it downloaded, the policy it cares
 * about, the chain it is on). `SolventSetOracle.verifyMembership` performs the
 * same checks on-chain; doing them client-side first turns an opaque revert
 * into a specific, readable error.
 */

/** Byte length of the committed public-values blob. */
export const MEMBERSHIP_PUBLIC_VALUES_LEN = 224;

/** The decoded membership statement. */
export interface MembershipPublicValues {
  /** The solvent-set root the proof is against (0x-prefixed). */
  solventSetRoot: string;
  /** The policy the proof is scoped to (0x-prefixed). */
  policyId: string;
  /** The set epoch the proof is against. */
  epoch: bigint;
  /** The prover's stable, unlinkable identity for this policy (0x-prefixed). */
  nullifierHash: string;
  /** The chain the proof is intended for. */
  chainId: bigint;
  /** The minimum consecutive-epoch streak proven (the exact streak stays private). */
  minStreak: bigint;
  /** The scope the nullifier is bound to (0x-prefixed). */
  scopeHash: string;
}

function stripPrefix(hex: string): string {
  return hex.trim().replace(/^0x/i, "");
}

function word(hex: string, index: number): string {
  return hex.slice(index * 64, (index + 1) * 64);
}

function wordToBigInt(hex: string, index: number): bigint {
  return BigInt(`0x${word(hex, index)}`);
}

/**
 * Decode a 224-byte membership public-values blob.
 *
 * @param publicValuesHex Hex string, 0x prefix optional — the
 *   `public_values_abi` field of `zkpof-client prove` output.
 * @throws If the blob is not exactly 224 bytes of valid hex.
 */
export function decodeMembershipPublicValues(
  publicValuesHex: string
): MembershipPublicValues {
  const hex = stripPrefix(publicValuesHex);
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Public values are not valid hex");
  }
  if (hex.length !== MEMBERSHIP_PUBLIC_VALUES_LEN * 2) {
    throw new Error(
      `Invalid public values length: expected ${MEMBERSHIP_PUBLIC_VALUES_LEN} bytes, got ${
        hex.length / 2
      }`
    );
  }
  // uint64 words must be left-padded with zeros, matching the Rust decoder
  // (crates/common/src/membership.rs) — a nonzero high half means the blob was
  // not produced by the membership program.
  for (const index of [2, 4, 5]) {
    if (!/^0{48}/.test(word(hex, index))) {
      throw new Error("Invalid public values: nonzero padding in a uint64 word");
    }
  }
  return {
    solventSetRoot: `0x${word(hex, 0)}`,
    policyId: `0x${word(hex, 1)}`,
    epoch: wordToBigInt(hex, 2),
    nullifierHash: `0x${word(hex, 3)}`,
    chainId: wordToBigInt(hex, 4),
    minStreak: wordToBigInt(hex, 5),
    scopeHash: `0x${word(hex, 6)}`,
  };
}

/** What the caller independently knows and wants the proof checked against. */
export interface MembershipExpectation {
  solventSetRoot?: string;
  policyId?: string;
  epoch?: number | bigint;
  chainId?: number | bigint;
  scopeHash?: string;
  /** The policy's "solvent for >= k epochs" requirement. */
  requiredMinStreak?: number | bigint;
}

/** One failed expectation. */
export interface MembershipCheckFailure {
  field: keyof MembershipExpectation | "minStreak";
  expected: string;
  actual: string;
}

/** Result of cross-checking decoded public values against expectations. */
export interface MembershipCheckResult {
  ok: boolean;
  failures: MembershipCheckFailure[];
}

function sameHex(a: string, b: string): boolean {
  return stripPrefix(a).toLowerCase() === stripPrefix(b).toLowerCase();
}

/**
 * Cross-check decoded public values against what the caller already knows.
 *
 * Only the fields present in `expected` are checked, so a dApp that cares
 * solely about "right policy, right chain, streak >= 3" can pass just those.
 * `requiredMinStreak` is the one inequality: the proof must attest to *at
 * least* the required streak.
 */
export function checkMembershipPublicValues(
  values: MembershipPublicValues,
  expected: MembershipExpectation
): MembershipCheckResult {
  const failures: MembershipCheckFailure[] = [];

  if (expected.solventSetRoot !== undefined && !sameHex(values.solventSetRoot, expected.solventSetRoot)) {
    failures.push({
      field: "solventSetRoot",
      expected: expected.solventSetRoot,
      actual: values.solventSetRoot,
    });
  }
  if (expected.policyId !== undefined && !sameHex(values.policyId, expected.policyId)) {
    failures.push({ field: "policyId", expected: expected.policyId, actual: values.policyId });
  }
  if (expected.scopeHash !== undefined && !sameHex(values.scopeHash, expected.scopeHash)) {
    failures.push({ field: "scopeHash", expected: expected.scopeHash, actual: values.scopeHash });
  }
  if (expected.epoch !== undefined && values.epoch !== BigInt(expected.epoch)) {
    failures.push({
      field: "epoch",
      expected: String(expected.epoch),
      actual: String(values.epoch),
    });
  }
  if (expected.chainId !== undefined && values.chainId !== BigInt(expected.chainId)) {
    failures.push({
      field: "chainId",
      expected: String(expected.chainId),
      actual: String(values.chainId),
    });
  }
  if (
    expected.requiredMinStreak !== undefined &&
    values.minStreak < BigInt(expected.requiredMinStreak)
  ) {
    failures.push({
      field: "minStreak",
      expected: `>= ${expected.requiredMinStreak}`,
      actual: String(values.minStreak),
    });
  }

  return { ok: failures.length === 0, failures };
}
