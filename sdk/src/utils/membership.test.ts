import { describe, it, expect } from "vitest";
import {
  decodeMembershipPublicValues,
  checkMembershipPublicValues,
  MEMBERSHIP_PUBLIC_VALUES_LEN,
} from "./membership";

/**
 * The same field values as `test_abi_roundtrip` in
 * `crates/common/src/membership.rs`, encoded with that module's layout. This
 * is the cross-language lock: if either side's word order or padding changes,
 * this vector fails.
 */
const VECTOR =
  "01".repeat(32) + // solventSetRoot
  "02".repeat(32) + // policyId
  "00".repeat(24) +
  "00000000deadbeef" + // epoch
  "03".repeat(32) + // nullifierHash
  "00".repeat(24) +
  "0000000000aa36a7" + // chainId = 11155111 (sepolia)
  "00".repeat(24) +
  "000000000000000c" + // minStreak = 12
  "07".repeat(32) + // scopeHash
  // --- presentation context ---
  "c0".repeat(32) + // policyConfigHash
  "00".repeat(12) +
  "ee".repeat(20) + // verifier
  "00".repeat(24) +
  "0000000000000001" + // verifierChainId = 1
  "ac".repeat(32) + // actionId
  "00".repeat(12) +
  "be".repeat(20) + // beneficiary
  "00".repeat(24) +
  "0000000000000007" + // nonce = 7
  "00".repeat(24) +
  "0000000001298be0"; // deadline = 19_500_000

describe("decodeMembershipPublicValues", () => {
  it("decodes the cross-language vector", () => {
    expect(VECTOR.length).toBe(MEMBERSHIP_PUBLIC_VALUES_LEN * 2);
    const values = decodeMembershipPublicValues(VECTOR);
    expect(values.solventSetRoot).toBe(`0x${"01".repeat(32)}`);
    expect(values.policyId).toBe(`0x${"02".repeat(32)}`);
    expect(values.epoch).toBe(0xdeadbeefn);
    expect(values.nullifierHash).toBe(`0x${"03".repeat(32)}`);
    expect(values.chainId).toBe(11155111n);
    expect(values.minStreak).toBe(12n);
    expect(values.scopeHash).toBe(`0x${"07".repeat(32)}`);
    expect(values.policyConfigHash).toBe(`0x${"c0".repeat(32)}`);
    expect(values.verifier).toBe(`0x${"ee".repeat(20)}`);
    expect(values.verifierChainId).toBe(1n);
    expect(values.actionId).toBe(`0x${"ac".repeat(32)}`);
    expect(values.beneficiary).toBe(`0x${"be".repeat(20)}`);
    expect(values.nonce).toBe(7n);
    expect(values.deadline).toBe(19_500_000n);
  });

  it("accepts a 0x prefix and surrounding whitespace", () => {
    const values = decodeMembershipPublicValues(`  0x${VECTOR}\n`);
    expect(values.chainId).toBe(11155111n);
  });

  it("rejects a wrong-length blob", () => {
    expect(() => decodeMembershipPublicValues(VECTOR.slice(0, -2))).toThrow(
      /expected 448 bytes, got 447/
    );
  });

  it("rejects non-hex input", () => {
    expect(() => decodeMembershipPublicValues("zz".repeat(448))).toThrow(/not valid hex/);
  });

  it("rejects nonzero padding in a uint64 word", () => {
    // Flip a byte inside the epoch word's zero padding.
    const corrupted = VECTOR.slice(0, 64 * 2) + "ff" + VECTOR.slice(64 * 2 + 2);
    expect(() => decodeMembershipPublicValues(corrupted)).toThrow(/nonzero padding/);
  });
});

describe("checkMembershipPublicValues", () => {
  const values = decodeMembershipPublicValues(VECTOR);

  it("passes when every expectation matches", () => {
    const result = checkMembershipPublicValues(values, {
      solventSetRoot: `0x${"01".repeat(32)}`,
      policyId: "02".repeat(32), // prefix-insensitive
      epoch: 0xdeadbeef,
      chainId: 11155111,
      scopeHash: `0x${"07".repeat(32)}`,
      requiredMinStreak: 12,
    });
    expect(result.ok).toBe(true);
    expect(result.failures).toEqual([]);
  });

  it("ignores fields the caller did not specify", () => {
    expect(checkMembershipPublicValues(values, { chainId: 11155111 }).ok).toBe(true);
  });

  it("treats minStreak as a lower bound", () => {
    expect(checkMembershipPublicValues(values, { requiredMinStreak: 11 }).ok).toBe(true);
    expect(checkMembershipPublicValues(values, { requiredMinStreak: 12 }).ok).toBe(true);
    const short = checkMembershipPublicValues(values, { requiredMinStreak: 13 });
    expect(short.ok).toBe(false);
    expect(short.failures[0]).toEqual({
      field: "minStreak",
      expected: ">= 13",
      actual: "12",
    });
  });

  it("reports every mismatched field", () => {
    const result = checkMembershipPublicValues(values, {
      policyId: `0x${"ab".repeat(32)}`,
      chainId: 1,
    });
    expect(result.ok).toBe(false);
    expect(result.failures.map((f) => f.field).sort()).toEqual(["chainId", "policyId"]);
  });

  it("catches a proof replayed from another policy's scope", () => {
    const result = checkMembershipPublicValues(values, {
      scopeHash: `0x${"99".repeat(32)}`,
    });
    expect(result.ok).toBe(false);
    expect(result.failures[0].field).toBe("scopeHash");
  });
});
