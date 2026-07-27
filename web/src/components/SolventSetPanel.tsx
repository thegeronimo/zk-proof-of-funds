/**
 * Solvent-set explorer — the auditor's view of a published epoch.
 *
 * The prove flow uses the set to build a witness; this page exists to answer
 * "should anyone believe this set at all": does the served list hash to the
 * served root, does that root match what the oracle stored, and was it *proven*
 * (Stage B) or merely asserted by the operator (Stage A)?
 *
 * Membership can still be checked here, and as everywhere it happens locally —
 * the full list is downloaded and searched in the browser.
 */

import { useMemo, useState } from "react";
import { useAccount, useConnect, useDisconnect } from "wagmi";
import type { SolventSetPath } from "@zk-proof-of-funds/sdk";
import { usePolicySelection } from "../hooks/usePolicySelection";
import { useSolventSet, findMembership, streakHistogram } from "../hooks/useSolventSet";
import { useOnChainSet, blocksUntilExpiry } from "../hooks/useOnChainSet";
import { HAS_ORACLE } from "../config/contracts";
import PolicyPicker from "./PolicyPicker";
import {
  Button,
  Callout,
  Card,
  CopyButton,
  DefinitionList,
  Field,
  Hex,
  PageHeader,
  Row,
  Spinner,
  StatusPill,
  TextInput,
  VerifiedPill,
} from "./ui";

const PAGE_SIZE = 25;

export default function SolventSetPanel() {
  const { policyId, policy, isValid } = usePolicySelection();
  const { address, isConnected } = useAccount();
  const { connectors, connect } = useConnect();
  const { disconnect } = useDisconnect();

  const set = useSolventSet();
  const onChain = useOnChainSet(policy?.chain_id);

  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState("");
  const [membership, setMembership] = useState<SolventSetPath | null>(null);
  const [membershipChecked, setMembershipChecked] = useState(false);

  async function load() {
    setPage(0);
    setMembership(null);
    setMembershipChecked(false);
    const result = await set.load(policyId);
    void onChain.load(policyId);
    if (result.info && address) {
      setMembership(await findMembership(result.entries, address));
      setMembershipChecked(true);
    }
  }

  const filtered = useMemo(() => {
    const needle = filter.trim().replace(/^0x/, "").toLowerCase();
    if (!needle) return set.entries;
    return set.entries.filter(([addr]) => addr.replace(/^0x/, "").toLowerCase().includes(needle));
  }, [set.entries, filter]);

  const histogram = useMemo(() => streakHistogram(set.entries), [set.entries]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const visible = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const expiry = blocksUntilExpiry(onChain);

  function downloadJson() {
    const blob = new Blob(
      [JSON.stringify({ info: set.info, entries: set.entries }, null, 2)],
      { type: "application/json" }
    );
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `solvent-set-${set.info?.epoch ?? "unknown"}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="max-w-4xl mx-auto">
      <PageHeader title="Solvent set">
        Every address meeting the policy threshold at the reference block, with the number of
        consecutive epochs it has qualified. Public data by construction — on a transparent chain,
        solvency already is.
      </PageHeader>

      <div className="space-y-6">
        <Card title="Policy">
          <PolicyPicker compact />
          <div className="mt-4">
            <Button onClick={load} disabled={set.loading || !isValid} full>
              {set.loading ? "Downloading and rebuilding…" : "Load set"}
            </Button>
          </div>
          {set.error && (
            <div className="mt-4">
              <Callout tone="bad" title="Could not load the set">
                {set.error}
              </Callout>
            </div>
          )}
        </Card>

        {set.info && (
          <Card
            title="Epoch summary"
            actions={
              <div className="flex items-center gap-2">
                <VerifiedPill state={set.rootVerified} verifiedLabel="root rebuilt locally" />
                <Button onClick={downloadJson} variant="ghost" size="sm">
                  Download JSON
                </Button>
              </div>
            }
          >
            <DefinitionList>
              <Row label="Epoch">{set.info.epoch}</Row>
              <Row label="Reference block">{set.info.block_number.toLocaleString()}</Row>
              <Row label="Addresses">{set.entries.length.toLocaleString()}</Row>
              <Row label="Served root">
                <Hex value={set.info.root} />
              </Row>
              <Row label="Rebuilt root">{set.localRoot ? <Hex value={set.localRoot} /> : "—"}</Row>
            </DefinitionList>
            {set.rootVerified === false && (
              <div className="mt-4">
                <Callout tone="bad" title="Root mismatch">
                  The entries served do not hash to the root served. Treat this set as untrusted.
                </Callout>
              </div>
            )}
          </Card>
        )}

        {set.info && (
          <OnChainRecord onChain={onChain} servedRoot={set.info.root} expiry={expiry} />
        )}

        {set.info && histogram.length > 0 && (
          <Card
            title="Streak distribution"
            subtitle="How long the set's members have been continuously solvent."
          >
            <div className="space-y-1.5">
              {histogram.slice(0, 10).map(([streak, count]) => (
                <div key={streak} className="flex items-center gap-3 text-sm">
                  <span className="w-24 shrink-0 text-gray-500">
                    {streak} epoch{streak === 1 ? "" : "s"}
                  </span>
                  <div className="flex-1 bg-gray-100 rounded-full h-2.5 overflow-hidden">
                    <div
                      className="bg-primary-500 h-full rounded-full"
                      style={{ width: `${(count / set.entries.length) * 100}%` }}
                    />
                  </div>
                  <span className="w-16 text-right font-mono text-xs text-gray-600">
                    {count.toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          </Card>
        )}

        {set.info && (
          <Card title="Check an address" subtitle="Searched locally against the downloaded list.">
            {isConnected ? (
              <div className="flex items-center justify-between gap-3 p-3 bg-green-50 rounded-lg mb-4">
                <span className="text-sm text-green-800 font-mono break-all">{address}</span>
                <button
                  onClick={() => disconnect()}
                  className="text-sm text-gray-500 hover:text-gray-700 shrink-0"
                >
                  Disconnect
                </button>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2 mb-4">
                {connectors.slice(0, 1).map((connector) => (
                  <Button key={connector.uid} onClick={() => connect({ connector })} size="sm">
                    Connect wallet
                  </Button>
                ))}
              </div>
            )}
            <Button
              onClick={async () => {
                if (!address) return;
                setMembership(await findMembership(set.entries, address));
                setMembershipChecked(true);
              }}
              disabled={!address}
              variant="ghost"
              full
            >
              Check my membership
            </Button>
            {membershipChecked && (
              <div className="mt-4">
                {membership ? (
                  <Callout tone="good" title="In the set">
                    Streak {membership.streak} · leaf index {membership.leafIndex}. Head to
                    “Prove” to turn this into a proof.
                  </Callout>
                ) : (
                  <Callout tone="warn" title="Not in this epoch's set">
                    Balance was below the threshold at the reference block.
                  </Callout>
                )}
              </div>
            )}
          </Card>
        )}

        {set.entries.length > 0 && (
          <Card
            title="Entries"
            subtitle={`Canonical order — leaf index is position in this list.`}
            actions={<CopyButton value={set.entries.map(([a]) => a).join("\n")} label="Copy addresses" />}
          >
            <div className="mb-3">
              <Field label="Filter by address">
                <TextInput value={filter} onChange={(v) => { setFilter(v); setPage(0); }} placeholder="0x… or any substring" mono />
              </Field>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-200">
                    <th className="py-2 pr-3 font-medium">#</th>
                    <th className="py-2 pr-3 font-medium">Address</th>
                    <th className="py-2 font-medium">Streak</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map(([addr, streak]) => {
                    const index = set.entries.findIndex(([a]) => a === addr);
                    const isMine =
                      address !== undefined &&
                      addr.replace(/^0x/, "").toLowerCase() ===
                        address.replace(/^0x/, "").toLowerCase();
                    return (
                      <tr
                        key={addr}
                        className={`border-b border-gray-100 ${isMine ? "bg-primary-50" : ""}`}
                      >
                        <td className="py-2 pr-3 font-mono text-xs text-gray-400">{index}</td>
                        <td className="py-2 pr-3 font-mono text-xs break-all">
                          0x{addr.replace(/^0x/, "")}
                          {isMine && <span className="ml-2 text-primary-600">← you</span>}
                        </td>
                        <td className="py-2 font-mono text-xs">{streak}</td>
                      </tr>
                    );
                  })}
                  {visible.length === 0 && (
                    <tr>
                      <td colSpan={3} className="py-6 text-center text-gray-500">
                        No addresses match that filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {pageCount > 1 && (
              <div className="flex items-center justify-between mt-4 text-sm">
                <Button
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  variant="ghost"
                  size="sm"
                >
                  Previous
                </Button>
                <span className="text-gray-500">
                  Page {page + 1} of {pageCount} · {filtered.length.toLocaleString()} entries
                </span>
                <Button
                  onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                  disabled={page >= pageCount - 1}
                  variant="ghost"
                  size="sm"
                >
                  Next
                </Button>
              </div>
            )}
          </Card>
        )}

        <p className="text-xs text-gray-400">
          The agent sees only that someone downloaded the set — never a query about a particular
          address. That is why there is no server-side path endpoint.
        </p>
      </div>
    </div>
  );
}

function OnChainRecord({
  onChain,
  servedRoot,
  expiry,
}: {
  onChain: ReturnType<typeof useOnChainSet>;
  servedRoot: string;
  expiry: bigint | null;
}) {
  if (!HAS_ORACLE) {
    return (
      <Card title="On-chain record">
        <Callout tone="neutral" title="No oracle configured">
          Set <code className="font-mono">VITE_ORACLE_ADDRESS</code> (and optionally{" "}
          <code className="font-mono">VITE_POLICY_REGISTRY_ADDRESS</code>) to see whether this root
          was published, whether it was proven, and when it expires.
        </Callout>
      </Card>
    );
  }
  if (onChain.loading) {
    return (
      <Card title="On-chain record">
        <Spinner label="Reading the oracle…" />
      </Card>
    );
  }
  if (onChain.error) {
    return (
      <Card title="On-chain record">
        <Callout tone="bad" title="Read failed">
          {onChain.error}
        </Callout>
      </Card>
    );
  }
  if (!onChain.entry) {
    return (
      <Card title="On-chain record">
        <Callout tone="warn" title="No root published for this policy">
          The agent has built a set, but nothing is on-chain, so no proof against it can be
          verified yet.
        </Callout>
      </Card>
    );
  }

  const matches =
    onChain.entry.root.toLowerCase() === `0x${servedRoot.replace(/^0x/, "")}`.toLowerCase();

  return (
    <Card
      title="On-chain record"
      subtitle={`SolventSetOracle set #${onChain.setIndex}${
        onChain.chainId ? ` · chain ${onChain.chainId}` : ""
      }`}
      actions={
        onChain.entry.proven ? (
          <StatusPill tone="good">✓ proven derivation</StatusPill>
        ) : (
          <StatusPill tone="warn">operator-asserted</StatusPill>
        )
      }
    >
      <DefinitionList>
        <Row label="Published root">
          <Hex value={onChain.entry.root} />
        </Row>
        <Row label="Matches agent">
          <VerifiedPill state={matches} verifiedLabel="same root" failedLabel="DIFFERENT ROOT" />
        </Row>
        <Row label="Epoch">{String(onChain.entry.epoch)}</Row>
        <Row label="Reference block">{onChain.entry.blockNumber.toLocaleString()}</Row>
        <Row label="Members">{onChain.entry.memberCount.toLocaleString()}</Row>
        <Row label="Published at">block {onChain.entry.publishedAt.toLocaleString()}</Row>
        <Row label="Expires in">
          {expiry === null ? (
            "unknown (registry not configured)"
          ) : expiry > 0n ? (
            `${expiry.toLocaleString()} blocks`
          ) : (
            <StatusPill tone="bad">expired</StatusPill>
          )}
        </Row>
        <Row label="Completeness">
          {onChain.requiresCompleteness ? "required (Stage B.2)" : "not required"}
        </Row>
        <Row label="Policy scope">
          {onChain.scopeHash ? <Hex value={onChain.scopeHash} truncate /> : "—"}
        </Row>
        <Row label="Membership vkey">
          {onChain.membershipVKey ? <Hex value={onChain.membershipVKey} truncate /> : "—"}
        </Row>
      </DefinitionList>
      {!onChain.entry.proven && (
        <div className="mt-4">
          <Callout tone="warn" title="Stage A root">
            Published with <code className="font-mono">publishRoot</code>: the operator asserted
            this membership list rather than proving each balance against the block's state root.
          </Callout>
        </div>
      )}
    </Card>
  );
}
