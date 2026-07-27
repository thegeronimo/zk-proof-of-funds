/**
 * The policy catalog, read from the repo's shared `config/policies.json` so the
 * app, the agent, and `Deploy.s.sol` all describe the same policies.
 *
 * Policy IDs are 32-byte hex — unreadable and error-prone to paste by hand, so
 * every screen picks from this catalog and keeps raw hex entry as an escape
 * hatch for policies that are not in the file.
 */

import catalog from "@zkpof/policies.json";

/** One entry of `config/policies.json`. */
export interface PolicyConfig {
  id: string;
  description: string;
  threshold_wei: number;
  token_address: string | null;
  chain_id: number;
  epoch_length_blocks: number;
  max_block_age: number;
  root_ttl_blocks: number;
  operator: string;
  scope: string;
  trusted_mode: boolean;
  active: boolean;
}

export const POLICIES: PolicyConfig[] = catalog as PolicyConfig[];

/** Look up a policy by ID, tolerating 0x-prefix and case differences. */
export function findPolicy(policyId: string): PolicyConfig | undefined {
  const target = policyId.replace(/^0x/, "").toLowerCase();
  return POLICIES.find((p) => p.id.replace(/^0x/, "").toLowerCase() === target);
}

/** Canonical 0x-prefixed lowercase form of a 32-byte hex ID. */
export function normalizePolicyId(policyId: string): string {
  return `0x${policyId.replace(/^0x/, "").toLowerCase()}`;
}

/** True if the string is a syntactically valid 32-byte hex policy ID. */
export function isValidPolicyId(policyId: string): boolean {
  return /^(0x)?[0-9a-fA-F]{64}$/.test(policyId.trim());
}

/**
 * Human-readable threshold. ERC-20 policies are denominated in the token's own
 * units, so only native-ETH thresholds get a wei → ETH conversion.
 */
export function formatThreshold(policy: PolicyConfig): string {
  if (policy.token_address) {
    return `${policy.threshold_wei.toLocaleString()} base units`;
  }
  const eth = policy.threshold_wei / 1e18;
  return `${eth.toLocaleString(undefined, { maximumFractionDigits: 6 })} ETH`;
}

/** Short asset label for chips and table cells. */
export function assetLabel(policy: PolicyConfig): string {
  return policy.token_address
    ? `ERC-20 ${policy.token_address.slice(0, 8)}…`
    : "Native ETH";
}
