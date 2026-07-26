/**
 * Downloading a solvent set and checking it — the shared core of the prove
 * flow and the set explorer.
 *
 * Two invariants this hook exists to enforce:
 *
 * 1. **The whole set is downloaded.** Asking the agent "is address X in the
 *    set" would reveal X; downloading everything is what makes the lookup
 *    oblivious (PRIVACY_V2.md §4.1).
 * 2. **The served root is never believed.** The tree is rebuilt from the
 *    entries in the browser and compared. A membership path against an
 *    unverified root proves nothing.
 */

import { useCallback, useState } from "react";
import type { SolventSetInfo, SolventSetEntryTuple, SolventSetPath } from "@zk-proof-of-funds/sdk";
import { computeSolventSetRoot, computeSolventSetPath } from "@zk-proof-of-funds/sdk";
import { apiClient } from "../services/apiClient";

export interface SolventSetState {
  info: SolventSetInfo | null;
  entries: SolventSetEntryTuple[];
  /** Root rebuilt in the browser (0x-prefixed), or null before a load. */
  localRoot: string | null;
  /** Whether the rebuilt root matches the served one. */
  rootVerified: boolean | null;
  loading: boolean;
  error: string | null;
}

const EMPTY: SolventSetState = {
  info: null,
  entries: [],
  localRoot: null,
  rootVerified: null,
  loading: false,
  error: null,
};

export function useSolventSet() {
  const [state, setState] = useState<SolventSetState>(EMPTY);

  const load = useCallback(async (policyId: string): Promise<SolventSetState> => {
    setState({ ...EMPTY, loading: true });
    try {
      const { info, entries } = await apiClient.fetchAllSolventSetEntries(policyId);
      const rebuilt = await computeSolventSetRoot(entries as SolventSetEntryTuple[]);
      const localRoot = `0x${rebuilt.replace(/^0x/, "")}`;
      const rootVerified =
        localRoot.toLowerCase() === `0x${info.root.replace(/^0x/, "")}`.toLowerCase();

      const next: SolventSetState = {
        info,
        entries: entries as SolventSetEntryTuple[],
        localRoot,
        rootVerified,
        loading: false,
        error: null,
      };
      setState(next);
      return next;
    } catch (err) {
      const next: SolventSetState = {
        ...EMPTY,
        error: err instanceof Error ? err.message : "Failed to load the solvent set",
      };
      setState(next);
      return next;
    }
  }, []);

  const reset = useCallback(() => setState(EMPTY), []);

  return { ...state, load, reset };
}

/**
 * Locate an address in a downloaded set and build its Merkle path — entirely
 * in the browser. Returns null when the address is not in the set.
 */
export async function findMembership(
  entries: SolventSetEntryTuple[],
  address: string
): Promise<SolventSetPath | null> {
  return computeSolventSetPath(entries, address);
}

/** Streak histogram for the explorer, highest streak first. */
export function streakHistogram(entries: SolventSetEntryTuple[]): [number, number][] {
  const counts = new Map<number, number>();
  for (const [, streak] of entries) {
    counts.set(streak, (counts.get(streak) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[0] - a[0]);
}
