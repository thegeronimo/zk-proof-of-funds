/**
 * The selected policy, shared across every screen and persisted.
 *
 * A policy ID is 32 bytes of hex. Re-entering it on each tab was the single
 * biggest friction point in the old app, so it is picked once and follows the
 * user around; the choice survives a reload.
 */

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  POLICIES,
  findPolicy,
  isValidPolicyId,
  normalizePolicyId,
  type PolicyConfig,
} from "../config/policies";

const STORAGE_KEY = "zkpof.policyId";

interface PolicySelection {
  /** Canonical 0x-prefixed policy ID, or "" when nothing is selected. */
  policyId: string;
  /** Catalog metadata, when the selected ID is a known policy. */
  policy: PolicyConfig | undefined;
  /** True when `policyId` is a syntactically valid 32-byte hex ID. */
  isValid: boolean;
  setPolicyId: (id: string) => void;
}

const PolicyContext = createContext<PolicySelection | null>(null);

function initialPolicyId(): string {
  const stored = typeof localStorage !== "undefined" ? localStorage.getItem(STORAGE_KEY) : null;
  if (stored && isValidPolicyId(stored)) return normalizePolicyId(stored);
  // Default to the first active catalog policy so the app is usable on arrival.
  const first = POLICIES.find((p) => p.active) ?? POLICIES[0];
  return first ? normalizePolicyId(first.id) : "";
}

export function PolicyProvider({ children }: { children: ReactNode }) {
  const [policyId, setPolicyIdState] = useState<string>(initialPolicyId);

  useEffect(() => {
    if (policyId) localStorage.setItem(STORAGE_KEY, policyId);
  }, [policyId]);

  const value = useMemo<PolicySelection>(
    () => ({
      policyId,
      policy: findPolicy(policyId),
      isValid: isValidPolicyId(policyId),
      setPolicyId: (id: string) =>
        setPolicyIdState(isValidPolicyId(id) ? normalizePolicyId(id) : id.trim()),
    }),
    [policyId]
  );

  return <PolicyContext.Provider value={value}>{children}</PolicyContext.Provider>;
}

export function usePolicySelection(): PolicySelection {
  const context = useContext(PolicyContext);
  if (!context) {
    throw new Error("usePolicySelection must be used inside a <PolicyProvider>");
  }
  return context;
}
