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
          { name: "epoch", type: "uint64" },
          { name: "blockNumber", type: "uint64" },
          { name: "publishedAt", type: "uint64" },
          { name: "memberCount", type: "uint32" },
          { name: "proven", type: "bool" },
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

/** The on-chain set entry, as returned by `getSetEntry`. */
export interface OnChainSetEntry {
  root: string;
  epoch: bigint;
  blockNumber: bigint;
  publishedAt: bigint;
  memberCount: number;
  proven: boolean;
}
