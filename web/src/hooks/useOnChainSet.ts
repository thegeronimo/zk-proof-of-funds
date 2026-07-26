/**
 * Reading what was actually published on-chain.
 *
 * The agent serves a set; `SolventSetOracle` records the root of authority.
 * Those can disagree — a stale agent, a set built but never published, or a
 * root published by a different operator. Only the chain says whether a root is
 * *proven* (Stage B, `publishRootProven`) or merely operator-asserted
 * (Stage A, `publishRoot`), and only the chain knows when it expires.
 */

import { useCallback, useState } from "react";
import { usePublicClient } from "wagmi";
import {
  ORACLE_ADDRESS,
  POLICY_REGISTRY_ADDRESS,
  SOLVENT_SET_ORACLE_ABI,
  POLICY_REGISTRY_ABI,
  type OnChainSetEntry,
} from "../config/contracts";

export interface OnChainSetState {
  configured: boolean;
  loading: boolean;
  error: string | null;
  /** Index of the latest published set, or null when none exists. */
  setIndex: number | null;
  entry: OnChainSetEntry | null;
  /** The policy's configured scope hash, as the contract computes it. */
  scopeHash: string | null;
  /** Whether the policy demands a Stage B.2 completeness proof. */
  requiresCompleteness: boolean | null;
  /** The membership verification key the oracle will check proofs against. */
  membershipVKey: string | null;
  /** Current chain head, for TTL math. */
  blockNumber: bigint | null;
  /** rootTTLBlocks from the registry, when it is configured. */
  rootTTLBlocks: bigint | null;
}

const EMPTY: OnChainSetState = {
  configured: ORACLE_ADDRESS !== null,
  loading: false,
  error: null,
  setIndex: null,
  entry: null,
  scopeHash: null,
  requiresCompleteness: null,
  membershipVKey: null,
  blockNumber: null,
  rootTTLBlocks: null,
};

export function useOnChainSet() {
  const publicClient = usePublicClient();
  const [state, setState] = useState<OnChainSetState>(EMPTY);

  const load = useCallback(
    async (policyId: string) => {
      if (!ORACLE_ADDRESS || !publicClient) {
        setState({ ...EMPTY, configured: false });
        return;
      }
      setState({ ...EMPTY, loading: true });
      try {
        const oracle = { address: ORACLE_ADDRESS, abi: SOLVENT_SET_ORACLE_ABI } as const;
        const policyIdHex = policyId as `0x${string}`;

        // Read the cheap, always-present values first; a policy with no
        // published set must still show its scope and vkey.
        const [setCount, scopeHash, requiresCompleteness, membershipVKey, blockNumber] =
          await Promise.all([
            publicClient.readContract({ ...oracle, functionName: "getSetCount", args: [policyIdHex] }),
            publicClient.readContract({
              ...oracle,
              functionName: "effectiveScopeHash",
              args: [policyIdHex],
            }),
            publicClient.readContract({
              ...oracle,
              functionName: "requiresCompleteness",
              args: [policyIdHex],
            }),
            publicClient.readContract({ ...oracle, functionName: "membershipVKey" }),
            publicClient.getBlockNumber(),
          ]);

        let setIndex: number | null = null;
        let entry: OnChainSetEntry | null = null;
        if (setCount > 0n) {
          setIndex = Number(setCount - 1n);
          const raw = await publicClient.readContract({
            ...oracle,
            functionName: "getSetEntry",
            args: [policyIdHex, setCount - 1n],
          });
          entry = {
            root: raw.root,
            epoch: raw.epoch,
            blockNumber: raw.blockNumber,
            publishedAt: raw.publishedAt,
            memberCount: raw.memberCount,
            proven: raw.proven,
          };
        }

        let rootTTLBlocks: bigint | null = null;
        if (POLICY_REGISTRY_ADDRESS) {
          try {
            const policy = await publicClient.readContract({
              address: POLICY_REGISTRY_ADDRESS,
              abi: POLICY_REGISTRY_ABI,
              functionName: "getPolicy",
              args: [policyIdHex],
            });
            rootTTLBlocks = policy.rootTTLBlocks;
          } catch {
            // An unregistered policy is not an error for this panel — TTL just
            // stays unknown.
          }
        }

        setState({
          configured: true,
          loading: false,
          error: null,
          setIndex,
          entry,
          scopeHash,
          requiresCompleteness,
          membershipVKey,
          blockNumber,
          rootTTLBlocks,
        });
      } catch (err) {
        setState({
          ...EMPTY,
          error: err instanceof Error ? err.message : "On-chain read failed",
        });
      }
    },
    [publicClient]
  );

  return { ...state, load };
}

/** Blocks left before a published root expires; null when TTL is unknown. */
export function blocksUntilExpiry(state: OnChainSetState): bigint | null {
  if (!state.entry || state.rootTTLBlocks === null || state.blockNumber === null) return null;
  return state.entry.publishedAt + state.rootTTLBlocks - state.blockNumber;
}
