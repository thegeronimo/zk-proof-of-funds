/**
 * Operator console — building sets and epochs, and inspecting agent state.
 *
 * These are the endpoints an agent operator drives. They were previously
 * reachable only by hand-rolled curl, which made the Stage A / Stage B
 * distinction — the difference between asserting a membership list and proving
 * it — invisible in the product.
 */

import { useState } from "react";
import type {
  AdminEpochsResponse,
  AdminMembersResponse,
  BuildSolventSetResponse,
  TriggerEpochResponse,
} from "@zk-proof-of-funds/sdk";
import { apiClient } from "../services/apiClient";
import { usePolicySelection } from "../hooks/usePolicySelection";
import { findPolicy } from "../config/policies";
import PolicyPicker from "./PolicyPicker";
import {
  Button,
  Callout,
  Card,
  DefinitionList,
  Field,
  Hex,
  PageHeader,
  Row,
  StatusPill,
  TextArea,
  TextInput,
} from "./ui";

export default function OperatorPanel() {
  const { policyId, isValid } = usePolicySelection();
  const policy = findPolicy(policyId);

  // Build parameters.
  const [candidates, setCandidates] = useState("");
  const [blockNumber, setBlockNumber] = useState("");
  const [thresholdWei, setThresholdWei] = useState("");
  const [tokenAddress, setTokenAddress] = useState("");
  const [discoverFrom, setDiscoverFrom] = useState("");
  const [discoverTo, setDiscoverTo] = useState("");
  const [proven, setProven] = useState(false);
  const [balanceSlot, setBalanceSlot] = useState("");

  const [building, setBuilding] = useState(false);
  const [buildResult, setBuildResult] = useState<BuildSolventSetResponse | null>(null);
  const [epochResult, setEpochResult] = useState<TriggerEpochResponse | null>(null);
  const [members, setMembers] = useState<AdminMembersResponse | null>(null);
  const [epochs, setEpochs] = useState<AdminEpochsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function run<T>(label: string, action: () => Promise<T>, onDone: (value: T) => void) {
    setError(null);
    setBusy(label);
    try {
      onDone(await action());
    } catch (err) {
      setError(err instanceof Error ? err.message : `${label} failed`);
    } finally {
      setBusy(null);
    }
  }

  async function buildSet() {
    setError(null);
    setBuilding(true);
    setBuildResult(null);
    try {
      const list = candidates
        .split(/[\s,]+/)
        .map((c) => c.trim())
        .filter(Boolean);
      const result = await apiClient.buildSolventSet(policyId, {
        candidates: list.length ? list : undefined,
        block_number: blockNumber.trim() ? Number(blockNumber) : undefined,
        threshold_wei: thresholdWei.trim() || undefined,
        token_address: tokenAddress.trim() || undefined,
        discover_from_block: discoverFrom.trim() ? Number(discoverFrom) : undefined,
        discover_to_block: discoverTo.trim() ? Number(discoverTo) : undefined,
        proven: proven || undefined,
        balance_slot: balanceSlot.trim() ? Number(balanceSlot) : undefined,
      });
      setBuildResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Build failed");
    } finally {
      setBuilding(false);
    }
  }

  const erc20ProvenNeedsSlot = proven && tokenAddress.trim() !== "" && balanceSlot.trim() === "";

  return (
    <div className="max-w-3xl mx-auto">
      <PageHeader title="Operator">
        Build solvent sets, run monitored-mode epochs, and inspect what the agent holds. These
        endpoints require the agent to have an RPC configured.
      </PageHeader>

      <div className="space-y-6">
        <Card title="Policy">
          <PolicyPicker compact />
          {policy && (
            <p className="text-xs text-gray-500 mt-3">
              Catalog default threshold: {policy.threshold_wei.toLocaleString()} (
              {policy.token_address ? "token base units" : "wei"})
              {policy.token_address && ` · token ${policy.token_address}`}
            </p>
          )}
        </Card>

        <Card
          title="Build a solvent set"
          subtitle="Samples balances at a reference block and commits the (address, streak) tree."
        >
          <div className="space-y-4">
            <Field
              label="Candidate addresses"
              hint="Whitespace- or comma-separated. For native ETH policies this is the candidate list."
            >
              <TextArea
                value={candidates}
                onChange={setCandidates}
                rows={4}
                placeholder="0xabc…&#10;0xdef…"
              />
            </Field>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                label="Reference block"
                hint="Leave empty for the blockhash-derived unpredictable sample — the anti-rented-solvency default."
              >
                <TextInput value={blockNumber} onChange={setBlockNumber} placeholder="latest−k" mono />
              </Field>
              <Field label="Threshold (wei)" hint="Defaults to 1 ETH.">
                <TextInput
                  value={thresholdWei}
                  onChange={setThresholdWei}
                  placeholder="1000000000000000000"
                  mono
                />
              </Field>
              <Field label="ERC-20 token" hint="Empty measures native ETH.">
                <TextInput value={tokenAddress} onChange={setTokenAddress} placeholder="0x…" mono />
              </Field>
              <Field
                label="balanceOf slot"
                hint="Required for proven ERC-20 builds."
                error={erc20ProvenNeedsSlot ? "Proven ERC-20 builds need the mapping slot." : undefined}
              >
                <TextInput value={balanceSlot} onChange={setBalanceSlot} placeholder="e.g. 9" mono />
              </Field>
              <Field label="Discover from block" hint="With a token: scan Transfer logs.">
                <TextInput value={discoverFrom} onChange={setDiscoverFrom} mono />
              </Field>
              <Field label="Discover to block">
                <TextInput value={discoverTo} onChange={setDiscoverTo} mono />
              </Field>
            </div>

            <label className="flex items-start gap-3 p-3 rounded-lg border border-gray-200 cursor-pointer hover:bg-gray-50">
              <input
                type="checkbox"
                checked={proven}
                onChange={(e) => setProven(e.target.checked)}
                className="mt-0.5 rounded border-gray-300"
              />
              <span className="text-sm">
                <span className="font-medium text-gray-900">Stage B — proven derivation</span>
                <span className="block text-gray-500 mt-0.5">
                  Verify an EIP-1186 proof per candidate against the block's state root, so the
                  result can be published permissionlessly via{" "}
                  <code className="font-mono text-xs">publishRootProven</code>. Slower; without it
                  the root rests on trusting this operator.
                </span>
              </span>
            </label>

            <Button
              onClick={buildSet}
              disabled={building || !isValid || erc20ProvenNeedsSlot}
              full
            >
              {building ? "Building…" : proven ? "Build (Stage B, proven)" : "Build (Stage A)"}
            </Button>
          </div>

          {buildResult && (
            <div className="mt-5">
              <Card
                title="Build result"
                actions={
                  buildResult.proven ? (
                    <StatusPill tone="good">✓ proven</StatusPill>
                  ) : (
                    <StatusPill tone="warn">operator-asserted</StatusPill>
                  )
                }
              >
                <DefinitionList>
                  <Row label="Epoch">{buildResult.epoch}</Row>
                  <Row label="Reference block">{buildResult.block_number.toLocaleString()}</Row>
                  <Row label="Members">{buildResult.member_count.toLocaleString()}</Row>
                  <Row label="Root">
                    <Hex value={buildResult.root} />
                  </Row>
                  {buildResult.candidate_count !== undefined && (
                    <Row label="Candidates">{buildResult.candidate_count.toLocaleString()}</Row>
                  )}
                  {buildResult.state_root && (
                    <Row label="State root">
                      <Hex value={buildResult.state_root} truncate />
                    </Row>
                  )}
                  {buildResult.prev_root && (
                    <Row label="Previous root">
                      <Hex value={buildResult.prev_root} truncate />
                    </Row>
                  )}
                </DefinitionList>
              </Card>
            </div>
          )}
        </Card>

        <Card
          title="Monitored mode (V1)"
          subtitle="Re-read every enrolled member's balance and record a new epoch."
        >
          <Button
            onClick={() =>
              run("Trigger epoch", () => apiClient.triggerEpoch(policyId), setEpochResult)
            }
            disabled={busy !== null || !isValid}
            variant="secondary"
            full
          >
            {busy === "Trigger epoch" ? "Running…" : "Trigger epoch"}
          </Button>
          {epochResult && (
            <div className="mt-4">
              <DefinitionList>
                <Row label="Epoch">{epochResult.epoch}</Row>
                <Row label="Block">{epochResult.block_number.toLocaleString()}</Row>
                <Row label="Members">{epochResult.member_count}</Row>
                <Row label="Root">
                  <Hex value={epochResult.root} />
                </Row>
              </DefinitionList>
              {epochResult.balance_updates?.length > 0 && (
                <p className="text-xs text-gray-500 mt-3">
                  {epochResult.balance_updates.filter((u) => u.solvent).length} of{" "}
                  {epochResult.balance_updates.length} members solvent this epoch.
                </p>
              )}
            </div>
          )}
        </Card>

        <Card title="Agent state">
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() => run("Members", () => apiClient.listMembers(policyId), setMembers)}
              disabled={busy !== null || !isValid}
              variant="ghost"
              size="sm"
            >
              {busy === "Members" ? "Loading…" : "List members"}
            </Button>
            <Button
              onClick={() => run("Epochs", () => apiClient.getEpochHistory(policyId), setEpochs)}
              disabled={busy !== null || !isValid}
              variant="ghost"
              size="sm"
            >
              {busy === "Epochs" ? "Loading…" : "Epoch history"}
            </Button>
          </div>

          {members && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold mb-2">
                Members ({members.members?.length ?? 0})
              </h3>
              <div className="max-h-64 overflow-y-auto border border-gray-200 rounded-lg">
                <table className="w-full text-xs">
                  <thead className="bg-gray-50 sticky top-0">
                    <tr className="text-left text-gray-500">
                      <th className="py-1.5 px-2 font-medium">Member ID</th>
                      <th className="py-1.5 px-2 font-medium">Status</th>
                      <th className="py-1.5 px-2 font-medium">Balance (wei)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(members.members ?? []).map((member) => (
                      <tr key={member.member_id} className="border-t border-gray-100">
                        <td className="py-1.5 px-2 font-mono break-all">{member.member_id}</td>
                        <td className="py-1.5 px-2">
                          <StatusPill tone={member.status === "solvent" ? "good" : "warn"}>
                            {member.status}
                          </StatusPill>
                        </td>
                        <td className="py-1.5 px-2 font-mono">{member.last_balance_wei}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {epochs && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold mb-2">Latest epoch</h3>
              {epochs.latest_epoch ? (
                <DefinitionList>
                  <Row label="Epoch">{epochs.latest_epoch.epoch}</Row>
                  <Row label="Block">{epochs.latest_epoch.block_number.toLocaleString()}</Row>
                  <Row label="Members">{epochs.latest_epoch.member_count}</Row>
                  <Row label="Published at">
                    block {epochs.latest_epoch.published_at_block.toLocaleString()}
                  </Row>
                  <Row label="Root">
                    <Hex value={epochs.latest_epoch.root} />
                  </Row>
                </DefinitionList>
              ) : (
                <p className="text-sm text-gray-500">No epochs recorded for this policy yet.</p>
              )}
            </div>
          )}
        </Card>

        {error && (
          <Callout tone="bad" title="Request failed">
            {error}
            <p className="mt-2 text-xs">
              "RPC not configured" means the agent was started without <code>RPC_URL</code>.
            </p>
          </Callout>
        )}
      </div>
    </div>
  );
}
