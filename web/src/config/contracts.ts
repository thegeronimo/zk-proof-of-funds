/**
 * On-chain contract wiring for the app's read path.
 *
 * The agent is not a trusted source for what has actually been published: it
 * serves the set, but the *root of record* lives in `SolventSetOracle`. Every
 * screen that shows a root therefore also reads the chain and compares, which
 * is the only way to see whether a set was published operator-trusted
 * (`publishRoot`) or proven (`publishRootProven`).
 *
 * Addresses come from the environment because they differ per deployment;
 * everything degrades to a clearly-labeled "not configured" state when unset.
 */

import type { Address } from "viem";

function envAddress(value: string | undefined): Address | null {
  if (!value) return null;
  return /^0x[0-9a-fA-F]{40}$/.test(value) ? (value as Address) : null;
}

export const ORACLE_ADDRESS = envAddress(import.meta.env.VITE_ORACLE_ADDRESS);
export const POLICY_REGISTRY_ADDRESS = envAddress(
  import.meta.env.VITE_POLICY_REGISTRY_ADDRESS
);

/**
 * The chain the oracle above is deployed on.
 *
 * An address alone is ambiguous: the same bytes are a different contract on
 * every chain. Without pinning this, reads follow whatever chain the wallet
 * happens to be on — which fails when the user is on the wrong network, and
 * silently reads an unrelated contract when some *other* deployment shares the
 * address. Unset falls back to the selected policy's own `chain_id`.
 */
export const ORACLE_CHAIN_ID: number | null = (() => {
  const raw = import.meta.env.VITE_ORACLE_CHAIN_ID;
  if (!raw) return null;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
})();

/** Whether on-chain reads are possible at all in this deployment. */
export const HAS_ORACLE = ORACLE_ADDRESS !== null;

/**
 * Minimal `SolventSetOracle` ABI — the views the app reads plus the two
 * verification entry points it generates calldata for.
 */
export const SOLVENT_SET_ORACLE_ABI = [
  {
    type: "function",
    name: "latestSetIndex",
    stateMutability: "view",
    inputs: [{ name: "policyId", type: "bytes32" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "getSetCount",
    stateMutability: "view",
    inputs: [{ name: "policyId", type: "bytes32" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "getSetEntry",
    stateMutability: "view",
    inputs: [
      { name: "policyId", type: "bytes32" },
      { name: "setIndex", type: "uint256" },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "root", type: "bytes32" },
          { name: "policyConfigHash", type: "bytes32" },
          { name: "membershipVKey", type: "bytes32" },
          { name: "derivationVKey", type: "bytes32" },
          { name: "epoch", type: "uint64" },
          { name: "blockNumber", type: "uint64" },
          { name: "publishedAt", type: "uint64" },
          { name: "validUntil", type: "uint64" },
          { name: "memberCount", type: "uint32" },
          { name: "provenance", type: "uint8" },
          { name: "scanStartBlock", type: "uint64" },
          { name: "scanEndBlock", type: "uint64" },
          { name: "revoked", type: "bool" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "effectiveScopeHash",
    stateMutability: "view",
    inputs: [{ name: "policyId", type: "bytes32" }],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    type: "function",
    name: "isNullifierUsed",
    stateMutability: "view",
    inputs: [
      { name: "policyId", type: "bytes32" },
      { name: "nullifierHash", type: "bytes32" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "requiresCompleteness",
    stateMutability: "view",
    inputs: [{ name: "policyId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "membershipVKey",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    type: "function",
    name: "verifyMembership",
    stateMutability: "view",
    inputs: [
      { name: "policyId", type: "bytes32" },
      { name: "setIndex", type: "uint256" },
      { name: "publicValues", type: "bytes" },
      { name: "proofBytes", type: "bytes" },
    ],
    outputs: [
      { name: "nullifierHash", type: "bytes32" },
      { name: "minStreak", type: "uint64" },
    ],
  },
  {
    type: "function",
    name: "verifyAndConsume",
    stateMutability: "nonpayable",
    inputs: [
      { name: "policyId", type: "bytes32" },
      { name: "setIndex", type: "uint256" },
      { name: "publicValues", type: "bytes" },
      { name: "proofBytes", type: "bytes" },
    ],
    outputs: [
      { name: "nullifierHash", type: "bytes32" },
      { name: "minStreak", type: "uint64" },
    ],
  },
] as const;

/** Minimal `PolicyRegistry` ABI — used to show the on-chain policy terms. */
export const POLICY_REGISTRY_ABI = [
  {
    type: "function",
    name: "getPolicy",
    stateMutability: "view",
    inputs: [{ name: "policyId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "thresholdWei", type: "uint256" },
          { name: "tokenAddress", type: "address" },
          { name: "chainId", type: "uint64" },
          { name: "epochLengthBlocks", type: "uint64" },
          { name: "maxBlockAge", type: "uint64" },
          { name: "rootTTLBlocks", type: "uint64" },
          { name: "operator", type: "address" },
          { name: "scope", type: "string" },
          { name: "trustedMode", type: "bool" },
          { name: "active", type: "bool" },
        ],
      },
    ],
  },
  {
    type: "function",
    name: "policyExists",
    stateMutability: "view",
    inputs: [{ name: "policyId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

/**
 * How a root's contents were established. Mirrors
 * `SolventSetOracle.Provenance` — deliberately not a boolean, because
 * "balances were proven" and "the candidate list was complete" are different
 * claims and the old single `proven` flag conflated them.
 */
export enum Provenance {
  /** The operator asserted this set. No cryptographic backing. */
  OperatorAsserted = 0,
  /** Every listed candidate's balance was proven. Says nothing about omissions. */
  BalancesProven = 1,
  /** Balances proven AND the candidate list covers a proven block range. */
  RangeScanProven = 2,
}

/** Human-readable, deliberately non-overstated provenance labels. */
export const PROVENANCE_LABEL: Record<Provenance, string> = {
  [Provenance.OperatorAsserted]: "Operator-asserted",
  [Provenance.BalancesProven]: "Balances proven (list may omit holders)",
  [Provenance.RangeScanProven]: "Balances proven + list covers scanned range",
};

/** The on-chain set entry, as returned by `getSetEntry`. */
export interface OnChainSetEntry {
  root: string;
  /** Policy semantics in force when this root was published. */
  policyConfigHash: string;
  /** The vkeys this root was accepted under (rotation does not affect it). */
  membershipVKey: string;
  derivationVKey: string;
  epoch: bigint;
  blockNumber: bigint;
  publishedAt: bigint;
  /** Absolute expiry, pinned at publication from the source block. */
  validUntil: bigint;
  memberCount: number;
  provenance: Provenance;
  scanStartBlock: bigint;
  scanEndBlock: bigint;
  revoked: boolean;
}
