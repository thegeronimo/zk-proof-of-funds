/**
 * Policy selection: pick from the shared catalog, or paste a raw ID for a
 * policy that is not in `config/policies.json`.
 */

import { useState } from "react";
import {
  POLICIES,
  assetLabel,
  formatThreshold,
  isValidPolicyId,
  type PolicyConfig,
} from "../config/policies";
import { usePolicySelection } from "../hooks/usePolicySelection";
import { Callout, Field, Hex, StatusPill, TextInput } from "./ui";

function PolicyCard({
  policy,
  selected,
  onSelect,
}: {
  policy: PolicyConfig;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      onClick={onSelect}
      className={`text-left w-full p-4 rounded-lg border transition-colors ${
        selected
          ? "border-primary-500 bg-primary-50 ring-1 ring-primary-500"
          : "border-gray-200 hover:border-gray-300 hover:bg-gray-50"
      }`}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <span className="font-medium text-gray-900 text-sm">{policy.description}</span>
        <div className="flex items-center gap-1.5 shrink-0">
          {!policy.active && <StatusPill tone="warn">inactive</StatusPill>}
          {policy.trusted_mode && <StatusPill tone="warn">trusted mode</StatusPill>}
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <StatusPill tone="info">{formatThreshold(policy)}</StatusPill>
        <StatusPill>{assetLabel(policy)}</StatusPill>
        <StatusPill>chain {policy.chain_id}</StatusPill>
        <StatusPill>epoch {policy.epoch_length_blocks} blocks</StatusPill>
      </div>
    </button>
  );
}

export default function PolicyPicker({ compact = false }: { compact?: boolean }) {
  const { policyId, policy, isValid, setPolicyId } = usePolicySelection();
  const [custom, setCustom] = useState(() => (policy ? "" : policyId));
  const [showCustom, setShowCustom] = useState(() => policyId !== "" && !policy);

  if (compact) {
    return (
      <div className="flex items-center gap-2 flex-wrap">
        <select
          value={policy ? policy.id : "__custom"}
          onChange={(e) => {
            if (e.target.value === "__custom") {
              setShowCustom(true);
            } else {
              setPolicyId(e.target.value);
              setShowCustom(false);
            }
          }}
          className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm bg-white focus:ring-2 focus:ring-primary-500"
        >
          {POLICIES.map((p) => (
            <option key={p.id} value={p.id}>
              {p.description}
            </option>
          ))}
          <option value="__custom">Custom policy ID…</option>
        </select>
        {(showCustom || !policy) && (
          <input
            value={custom}
            onChange={(e) => {
              setCustom(e.target.value);
              setPolicyId(e.target.value);
            }}
            placeholder="0x… (32-byte hex)"
            className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm font-mono w-72 focus:ring-2 focus:ring-primary-500"
          />
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        {POLICIES.map((p) => (
          <PolicyCard
            key={p.id}
            policy={p}
            selected={policy?.id === p.id}
            onSelect={() => {
              setPolicyId(p.id);
              setShowCustom(false);
            }}
          />
        ))}
      </div>

      <div>
        <button
          onClick={() => setShowCustom((v) => !v)}
          className="text-sm text-primary-700 hover:text-primary-900 font-medium"
        >
          {showCustom ? "− Hide custom policy ID" : "+ Use a policy ID not in the catalog"}
        </button>
        {showCustom && (
          <div className="mt-3">
            <Field
              label="Custom policy ID"
              hint="32-byte hex. Used as-is; catalog metadata (threshold, asset) will be unavailable."
              error={custom && !isValidPolicyId(custom) ? "Must be 64 hex characters." : undefined}
            >
              <TextInput
                value={custom}
                onChange={(value) => {
                  setCustom(value);
                  setPolicyId(value);
                }}
                placeholder="0x0000…0001"
                mono
              />
            </Field>
          </div>
        )}
      </div>

      {isValid && (
        <Callout tone="info" title="Selected policy">
          <div className="flex flex-wrap items-center gap-2">
            <Hex value={policyId} />
            {!policy && <StatusPill tone="warn">not in catalog</StatusPill>}
          </div>
        </Callout>
      )}
    </div>
  );
}
