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
  ORACLE_CHAIN_ID,
  POLICY_REGISTRY_ADDRESS,
  SOLVENT_SET_ORACLE_ABI,
  POLICY_REGISTRY_ABI,
  Provenance,
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
  /** The chain these values were actually read from. */
  chainId: number | null;
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
  chainId: null,
};

/**
 * @param policyChainId The selected policy's chain, used when
 *   `VITE_ORACLE_CHAIN_ID` is not set. Passing neither leaves the chain up to
 *   wagmi, which is only correct when the wallet is already on the right one.
 */
export function useOnChainSet(policyChainId?: number) {
  const targetChainId = ORACLE_CHAIN_ID ?? policyChainId;
  // Pinning chainId makes the read independent of the connected wallet's
  // network — without it an unconnected app silently reads wagmi's first
  // configured chain.
  const publicClient = usePublicClient(
    targetChainId ? { chainId: targetChainId } : undefined
  );
  const [state, setState] = useState<OnChainSetState>(EMPTY);

  const load = useCallback(
    async (policyId: string) => {
      if (!ORACLE_ADDRESS) {
        setState({ ...EMPTY, configured: false });
        return;
      }
      if (!publicClient) {
        // wagmi has no transport for the pinned chain, so there is nothing to
        // read from. Say which chain rather than reading the wrong one.
        setState({
          ...EMPTY,
          error: targetChainId
            ? `No RPC configured for chain ${targetChainId} — add it to the wagmi config in hooks/useWeb3.ts.`
            : "No chain selected for on-chain reads. Set VITE_ORACLE_CHAIN_ID.",
          chainId: targetChainId ?? null,
        });
        return;
      }
      setState({ ...EMPTY, loading: true, chainId: targetChainId ?? null });
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
            policyConfigHash: raw.policyConfigHash,
            membershipVKey: raw.membershipVKey,
            derivationVKey: raw.derivationVKey,
            epoch: raw.epoch,
            blockNumber: raw.blockNumber,
            publishedAt: raw.publishedAt,
            validUntil: raw.validUntil,
            memberCount: raw.memberCount,
            provenance: raw.provenance as Provenance,
            scanStartBlock: raw.scanStartBlock,
            scanEndBlock: raw.scanEndBlock,
            revoked: raw.revoked,
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
          chainId: targetChainId ?? null,
        });
      } catch (err) {
        setState({
          ...EMPTY,
          error: err instanceof Error ? err.message : "On-chain read failed",
          chainId: targetChainId ?? null,
        });
      }
    },
    [publicClient, targetChainId]
  );

  return { ...state, load };
}

/**
 * Blocks left before a published root expires; null when unknown.
 *
 * Read from the entry's own pinned `validUntil`, never recomputed from the
 * policy's current TTL — the owner can change that, and a historical
 * attestation's lifetime must not move under it (review §4.6).
 */
export function blocksUntilExpiry(state: OnChainSetState): bigint | null {
  if (!state.entry || state.blockNumber === null) return null;
  return state.entry.validUntil - state.blockNumber;
}

/** Why a policy is not safe to prove against right now. */
export interface ProvenanceGate {
  ok: boolean;
  reasons: string[];
}

/**
 * Decide whether it is safe to generate a proof against this policy's
 * published root.
 *
 * The app previously *displayed* provenance warnings but let the user
 * continue regardless — including when no oracle was configured, the read
 * failed, no root was published, or the agent and chain disagreed (review
 * finding R7). In production the flow fails closed: every one of these has
 * to hold, and the specific failures are named so the user knows what broke.
 *
 * @param servedRoot The root the agent served.
 * @param localRootVerified Whether the browser's own rebuild matched it.
 */
export function provenanceGate(
  state: OnChainSetState,
  servedRoot: string | null,
  localRootVerified: boolean | null
): ProvenanceGate {
  const reasons: string[] = [];

  if (localRootVerified === false) {
    reasons.push("The tree rebuilt in this browser does not hash to the root the agent served.");
  } else if (localRootVerified === null) {
    reasons.push("The served set has not been rebuilt and verified locally yet.");
  }

  if (!state.configured) {
    reasons.push("No SolventSetOracle is configured, so nothing can be checked against the chain.");
  } else if (state.error) {
    reasons.push(`The on-chain read failed: ${state.error}`);
  } else if (state.loading) {
    reasons.push("The on-chain read has not finished.");
  } else if (!state.entry) {
    reasons.push("No root has been published on-chain for this policy.");
  } else {
    if (servedRoot && state.entry.root.toLowerCase() !== servedRoot.toLowerCase()) {
      reasons.push("The agent's root differs from the root published on-chain.");
    }
    if (state.entry.revoked) {
      reasons.push("This root has been revoked by the oracle owner.");
    }
    const remaining = blocksUntilExpiry(state);
    if (remaining !== null && remaining <= 0n) {
      reasons.push("The published root has expired; verification would revert.");
    }
    if (
      state.requiresCompleteness &&
      state.entry.provenance !== Provenance.RangeScanProven
    ) {
      reasons.push(
        "This policy requires a completeness-proven root, but the published root is not one."
      );
    }
  }

  return { ok: reasons.length === 0, reasons };
}
