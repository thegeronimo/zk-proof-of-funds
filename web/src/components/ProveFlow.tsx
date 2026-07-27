/**
 * The Privacy V2 prove flow (PRIVACY_V2.md §4.1) — the app's main path.
 *
 * Four steps: choose a policy, download and independently rebuild the solvent
 * set, locate your address in it locally, then produce the membership proof.
 *
 * The last step is a deliberate handoff to `zkpof-client`. SP1 cannot prove in
 * a browser and PLUME nullifiers need raw key access, so the proof is generated
 * on the user's own machine (PRIVACY_V2.md §7). What this screen can do is make
 * that handoff exact: it emits the fully-populated command, then takes the
 * CLI's JSON back and re-derives every claim in it against values the browser
 * already knows — so a mismatched root, epoch, chain, or scope is a readable
 * error here rather than an opaque revert on-chain.
 *
 * Nothing about the user's address is ever sent anywhere: the full set is
 * downloaded and searched locally.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useAccount, useChainId, useConnect, useDisconnect } from "wagmi";
import { encodeFunctionData } from "viem";
import type { SolventSetPath } from "@zk-proof-of-funds/sdk";
import {
  decodeMembershipPublicValues,
  checkMembershipPublicValues,
  type MembershipPublicValues,
  type MembershipCheckResult,
} from "@zk-proof-of-funds/sdk";
import { defaultScopeHash } from "@zk-proof-of-funds/sdk/plume";
import { AGENT_PUBLIC_URL } from "../services/apiClient";
import { usePolicySelection } from "../hooks/usePolicySelection";
import { useSolventSet, findMembership } from "../hooks/useSolventSet";
import { useOnChainSet, blocksUntilExpiry } from "../hooks/useOnChainSet";
import { ORACLE_ADDRESS, SOLVENT_SET_ORACLE_ABI, HAS_ORACLE } from "../config/contracts";
import { formatThreshold, assetLabel } from "../config/policies";
import PolicyPicker from "./PolicyPicker";
import {
  Button,
  Callout,
  Card,
  CodeBlock,
  CopyButton,
  DefinitionList,
  Field,
  Hex,
  PageHeader,
  Row,
  Spinner,
  StatusPill,
  Stepper,
  TextArea,
  TextInput,
  VerifiedPill,
  type Step,
} from "./ui";

const STEPS: Step[] = [
  { id: "policy", label: "Policy" },
  { id: "set", label: "Solvent set" },
  { id: "membership", label: "Membership" },
  { id: "proof", label: "Proof" },
];

/** Parsed `zkpof-client prove` output. */
interface CliProveOutput {
  mode: "execute" | "groth16";
  publicValuesAbi: string;
  proofBytes: string | null;
}

function parseCliOutput(raw: string): CliProveOutput {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Not valid JSON — paste the whole object printed by zkpof-client prove.");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("Expected a JSON object from zkpof-client prove.");
  }
  const record = parsed as Record<string, unknown>;
  const publicValuesAbi = record.public_values_abi;
  if (typeof publicValuesAbi !== "string") {
    throw new Error("Missing `public_values_abi` — is this the output of `zkpof-client prove`?");
  }
  const mode = record.mode === "groth16" ? "groth16" : "execute";
  const proofBytes = typeof record.proof_bytes === "string" ? record.proof_bytes : null;
  return { mode, publicValuesAbi, proofBytes };
}

function hexArg(value: string): `0x${string}` {
  return `0x${value.replace(/^0x/, "")}` as `0x${string}`;
}

export default function ProveFlow() {
  const { policyId, policy, isValid } = usePolicySelection();
  const { address, isConnected } = useAccount();
  const { connectors, connect } = useConnect();
  const { disconnect } = useDisconnect();
  const walletChainId = useChainId();

  const [step, setStep] = useState(0);
  const [furthest, setFurthest] = useState(0);

  const set = useSolventSet();
  const onChain = useOnChainSet(policy?.chain_id);

  // Step 3 — local membership lookup.
  const [manualAddress, setManualAddress] = useState("");
  const [membership, setMembership] = useState<SolventSetPath | null>(null);
  const [membershipChecked, setMembershipChecked] = useState(false);
  const [membershipError, setMembershipError] = useState<string | null>(null);

  // Step 4 — CLI handoff.
  const [agentUrl, setAgentUrl] = useState(AGENT_PUBLIC_URL);
  const [minStreak, setMinStreak] = useState("1");
  const [chainId, setChainId] = useState("");
  const [executeOnly, setExecuteOnly] = useState(false);
  const [cliOutput, setCliOutput] = useState("");
  const [decoded, setDecoded] = useState<MembershipPublicValues | null>(null);
  const [publicValuesHex, setPublicValuesHex] = useState<string | null>(null);
  const [cliMode, setCliMode] = useState<"execute" | "groth16" | null>(null);
  const [proofBytes, setProofBytes] = useState<string | null>(null);
  const [check, setCheck] = useState<MembershipCheckResult | null>(null);
  const [decodeError, setDecodeError] = useState<string | null>(null);

  const lookupAddress = isConnected && address ? address : manualAddress.trim();

  // The scope the nullifier binds to. The contract is authoritative when it is
  // reachable; otherwise the policy's default derivation is what the CLI uses.
  const derivedScope = useMemo(() => {
    if (!isValid) return null;
    try {
      return `0x${defaultScopeHash(policyId).replace(/^0x/, "")}`;
    } catch {
      return null;
    }
  }, [policyId, isValid]);
  const effectiveScope = onChain.scopeHash ?? derivedScope;
  const scopeIsCustom =
    onChain.scopeHash !== null &&
    derivedScope !== null &&
    onChain.scopeHash.toLowerCase() !== derivedScope.toLowerCase();

  // Default the target chain to the policy's, falling back to the wallet's.
  useEffect(() => {
    if (chainId) return;
    if (policy) setChainId(String(policy.chain_id));
    else if (walletChainId) setChainId(String(walletChainId));
  }, [policy, walletChainId, chainId]);

  /** Move to a step. */
  const advance = useCallback((to: number) => {
    setStep(to);
    setFurthest((f) => Math.max(f, to));
  }, []);

  /**
   * Make a later step reachable without jumping to it. Results worth reading —
   * the root verification, the on-chain provenance, your streak — render on the
   * step that produced them, so auto-advancing would skip past them.
   */
  const unlock = useCallback((to: number) => {
    setFurthest((f) => Math.max(f, to));
  }, []);

  async function loadSet() {
    const result = await set.load(policyId);
    void onChain.load(policyId);
    if (result.info) {
      setMembership(null);
      setMembershipChecked(false);
      unlock(2);
    }
  }

  async function checkMembership() {
    setMembershipError(null);
    if (!lookupAddress) {
      setMembershipError("Connect a wallet or paste an address to check.");
      return;
    }
    try {
      const path = await findMembership(set.entries, lookupAddress);
      setMembership(path);
      setMembershipChecked(true);
      if (path) unlock(3);
    } catch (err) {
      setMembershipError(err instanceof Error ? err.message : "Lookup failed");
      setMembershipChecked(false);
    }
  }

  const proveCommand = useMemo(() => {
    const parts = [
      "zkpof-client prove",
      "  --sk <YOUR_32_BYTE_HEX_KEY>",
      `  --policy ${policyId}`,
      `  --agent ${agentUrl}`,
      `  --min-streak ${minStreak || "1"}`,
      `  --chain-id ${chainId || "1"}`,
    ];
    // Only pass --scope when the policy uses a non-default (shared) scope;
    // otherwise the CLI derives the same value the contract expects.
    if (scopeIsCustom && onChain.scopeHash) parts.push(`  --scope ${onChain.scopeHash}`);
    if (executeOnly) parts.push("  --execute-only");
    return parts.join(" \\\n");
  }, [policyId, agentUrl, minStreak, chainId, executeOnly, scopeIsCustom, onChain.scopeHash]);

  function verifyCliOutput() {
    setDecodeError(null);
    setDecoded(null);
    setPublicValuesHex(null);
    setCheck(null);
    setProofBytes(null);
    setCliMode(null);
    try {
      const output = parseCliOutput(cliOutput);
      const values = decodeMembershipPublicValues(output.publicValuesAbi);
      const result = checkMembershipPublicValues(values, {
        // The root the browser rebuilt itself — not the one the agent served.
        solventSetRoot: set.localRoot ?? undefined,
        policyId,
        epoch: set.info?.epoch,
        chainId: chainId ? Number(chainId) : undefined,
        scopeHash: effectiveScope ?? undefined,
        requiredMinStreak: minStreak ? Number(minStreak) : undefined,
      });
      setDecoded(values);
      setPublicValuesHex(output.publicValuesAbi);
      setCheck(result);
      setCliMode(output.mode);
      setProofBytes(output.proofBytes);
    } catch (err) {
      setDecodeError(err instanceof Error ? err.message : "Could not read that output");
    }
  }

  const calldata = useMemo(() => {
    if (!publicValuesHex || !proofBytes || onChain.setIndex === null) return null;
    try {
      const args = [
        hexArg(policyId),
        BigInt(onChain.setIndex),
        hexArg(publicValuesHex),
        hexArg(proofBytes),
      ] as const;
      return {
        verify: encodeFunctionData({
          abi: SOLVENT_SET_ORACLE_ABI,
          functionName: "verifyMembership",
          args,
        }),
        consume: encodeFunctionData({
          abi: SOLVENT_SET_ORACLE_ABI,
          functionName: "verifyAndConsume",
          args,
        }),
      };
    } catch {
      return null;
    }
  }, [publicValuesHex, proofBytes, onChain.setIndex, policyId]);

  const expiry = blocksUntilExpiry(onChain);

  return (
    <div className="max-w-3xl mx-auto">
      <PageHeader title="Prove solvency">
        Prove you hold enough funds without revealing which address holds them. The set of
        qualifying addresses is public; your position in it stays private, and this page never
        sends your address anywhere.
      </PageHeader>

      <Stepper steps={STEPS} current={step} furthest={furthest} onSelect={setStep} />

      {/* ── Step 1: policy ─────────────────────────────────────────────── */}
      {step === 0 && (
        <div className="space-y-6">
          <Card title="Choose a policy" subtitle="What you want to prove, and against which asset.">
            <PolicyPicker />
          </Card>
          {policy && (
            <Card title="Policy terms">
              <DefinitionList>
                <Row label="Threshold">{formatThreshold(policy)}</Row>
                <Row label="Asset">{assetLabel(policy)}</Row>
                <Row label="Chain">{policy.chain_id}</Row>
                <Row label="Epoch length">{policy.epoch_length_blocks} blocks</Row>
                <Row label="Root TTL">{policy.root_ttl_blocks.toLocaleString()} blocks</Row>
                <Row label="Scope">
                  {derivedScope ? <Hex value={derivedScope} truncate /> : "—"}
                </Row>
              </DefinitionList>
            </Card>
          )}
          <Button onClick={() => advance(1)} disabled={!isValid} full>
            Continue
          </Button>
        </div>
      )}

      {/* ── Step 2: download and verify the set ────────────────────────── */}
      {step === 1 && (
        <div className="space-y-6">
          <Card
            title="Download the solvent set"
            subtitle="The whole list is fetched and re-hashed here. Downloading everything is what keeps the lookup private."
          >
            <Button onClick={loadSet} disabled={set.loading || !isValid} full>
              {set.loading ? "Downloading and rebuilding…" : "Download set"}
            </Button>
            {set.error && (
              <div className="mt-4">
                <Callout tone="bad" title="Could not load the set">
                  {set.error}
                  <p className="mt-2 text-xs">
                    A 404 means no set has been built for this policy yet — an operator builds one
                    from the Operator tab.
                  </p>
                </Callout>
              </div>
            )}
          </Card>

          {set.info && (
            <Card
              title="Set contents"
              actions={<VerifiedPill state={set.rootVerified} verifiedLabel="root rebuilt locally" />}
            >
              <DefinitionList>
                <Row label="Epoch">{set.info.epoch}</Row>
                <Row label="Reference block">{set.info.block_number.toLocaleString()}</Row>
                <Row label="Addresses">{set.entries.length.toLocaleString()}</Row>
                <Row label="Served root">
                  <Hex value={set.info.root} />
                </Row>
                <Row label="Rebuilt root">
                  {set.localRoot ? <Hex value={set.localRoot} /> : "—"}
                </Row>
              </DefinitionList>
              {set.rootVerified === false && (
                <div className="mt-4">
                  <Callout tone="bad" title="Root mismatch — do not use this set">
                    The tree rebuilt from the served entries does not hash to the served root. The
                    agent is serving inconsistent data; a proof against it would fail on-chain.
                  </Callout>
                </div>
              )}
            </Card>
          )}

          {set.info && <OnChainPanel onChain={onChain} servedRoot={set.info.root} expiry={expiry} />}

          {set.info && (
            <Button onClick={() => advance(2)} disabled={set.rootVerified === false} full>
              Continue
            </Button>
          )}
        </div>
      )}

      {/* ── Step 3: local membership ───────────────────────────────────── */}
      {step === 2 && (
        <div className="space-y-6">
          <Card
            title="Find yourself in the set"
            subtitle="Runs entirely in this browser against the downloaded list."
          >
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
              <div className="space-y-3 mb-4">
                <div className="flex flex-wrap gap-2">
                  {connectors.map((connector) => (
                    <Button key={connector.uid} onClick={() => connect({ connector })} size="sm">
                      Connect {connector.name}
                    </Button>
                  ))}
                </div>
                <Field
                  label="…or check an address directly"
                  hint="Never transmitted — the search happens against the list already in memory."
                >
                  <TextInput
                    value={manualAddress}
                    onChange={setManualAddress}
                    placeholder="0x…"
                    mono
                  />
                </Field>
              </div>
            )}
            <Button onClick={checkMembership} disabled={!lookupAddress || !set.entries.length} full>
              Check membership locally
            </Button>
            {membershipError && (
              <p className="text-sm text-red-600 mt-3">{membershipError}</p>
            )}
            {!set.entries.length && (
              <p className="text-sm text-gray-500 mt-3">
                Load a solvent set first (step 2).
              </p>
            )}
          </Card>

          {membershipChecked && membership && (
            <Card title="You are in the set" actions={<StatusPill tone="good">✓ member</StatusPill>}>
              <DefinitionList>
                <Row label="Streak">
                  {membership.streak} consecutive epoch{membership.streak === 1 ? "" : "s"}
                </Row>
                <Row label="Leaf index">{membership.leafIndex.toLocaleString()}</Row>
                <Row label="Path length">{membership.siblings.length} siblings</Row>
              </DefinitionList>
              <div className="mt-4">
                <Callout tone="info">
                  Your streak is the ceiling on what you can prove: a policy demanding
                  “solvent for ≥ k epochs” needs streak ≥ k. The proof reveals only that the
                  minimum is met, never the exact streak.
                </Callout>
              </div>
              <div className="mt-4">
                <Button onClick={() => advance(3)} full>
                  Continue to proof
                </Button>
              </div>
            </Card>
          )}

          {membershipChecked && !membership && (
            <Callout tone="warn" title="Not in this epoch's set">
              That address did not meet the threshold at the reference block
              {set.info ? ` (block ${set.info.block_number.toLocaleString()})` : ""}. It will be
              included in a future epoch once it qualifies.
            </Callout>
          )}
        </div>
      )}

      {/* ── Step 4: CLI handoff and verification ───────────────────────── */}
      {step === 3 && (
        <div className="space-y-6">
          <Callout tone="warn" title="This step runs on your machine, not in the browser">
            The membership proof needs your secret key and an SP1 prover — neither belongs in (or
            is possible in) a web page. Run the command below locally; the key never leaves your
            machine, and the agent never learns which address you are.
          </Callout>

          <Card title="Proof parameters">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Agent URL" hint="Where the CLI downloads the set from.">
                <TextInput value={agentUrl} onChange={setAgentUrl} mono />
              </Field>
              <Field
                label="Minimum streak"
                hint={
                  membership
                    ? `Your streak is ${membership.streak}. Must be ≤ that.`
                    : "The relying protocol's requirement."
                }
                error={
                  membership && Number(minStreak) > membership.streak
                    ? `Your streak is only ${membership.streak} — the proof will fail.`
                    : undefined
                }
              >
                <TextInput value={minStreak} onChange={setMinStreak} mono />
              </Field>
              <Field label="Chain ID" hint="The chain the proof will be verified on.">
                <TextInput value={chainId} onChange={setChainId} mono />
              </Field>
              <Field label="Mode" hint="Execute-only skips Groth16 — useful to sanity-check first.">
                <label className="flex items-center gap-2 text-sm text-gray-700 mt-2">
                  <input
                    type="checkbox"
                    checked={executeOnly}
                    onChange={(e) => setExecuteOnly(e.target.checked)}
                    className="rounded border-gray-300"
                  />
                  Emulate only (no proof bytes)
                </label>
              </Field>
            </div>
            {scopeIsCustom && (
              <div className="mt-4">
                <Callout tone="info" title="This policy uses a shared scope">
                  The oracle expects a nullifier bound to a non-default scope, so the command
                  passes <code className="font-mono">--scope</code> explicitly.
                </Callout>
              </div>
            )}
          </Card>

          <Card title="Run this" subtitle="Everything is filled in except your key.">
            <CodeBlock code={proveCommand} language="bash" />
          </Card>

          <Card
            title="Paste the output"
            subtitle="Every field is re-checked against what this browser already verified."
          >
            <TextArea
              value={cliOutput}
              onChange={setCliOutput}
              rows={7}
              placeholder={'{\n  "mode": "groth16",\n  "proof_bytes": "…",\n  "public_values_abi": "…"\n}'}
            />
            <div className="mt-3">
              <Button onClick={verifyCliOutput} disabled={!cliOutput.trim()} full>
                Decode and verify
              </Button>
            </div>
            {decodeError && <p className="text-sm text-red-600 mt-3">{decodeError}</p>}
          </Card>

          {decoded && check && (
            <ProofResult
              values={decoded}
              check={check}
              mode={cliMode}
              proofBytes={proofBytes}
              onChain={onChain}
              calldata={calldata}
            />
          )}
        </div>
      )}
    </div>
  );
}

function OnChainPanel({
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
          Set <code className="font-mono">VITE_ORACLE_ADDRESS</code> to compare the agent's set
          against what <code className="font-mono">SolventSetOracle</code> has actually published,
          including whether the root was proven or operator-asserted.
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
        <Callout tone="warn" title="Nothing published for this policy">
          The agent has a set, but no root for it exists on-chain, so no dApp can verify a proof
          against it yet.
        </Callout>
      </Card>
    );
  }

  const matches = onChain.entry.root.toLowerCase() === `0x${servedRoot.replace(/^0x/, "")}`.toLowerCase();
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
      </DefinitionList>
      {!onChain.entry.proven && (
        <div className="mt-4">
          <Callout tone="warn">
            This root was published with <code className="font-mono">publishRoot</code> — the
            operator asserted the membership list rather than proving it. Proofs against it still
            verify, but the set's contents rest on trusting the operator.
          </Callout>
        </div>
      )}
      {!matches && (
        <div className="mt-4">
          <Callout tone="bad" title="The agent and the chain disagree">
            A proof built from the agent's set will be rejected by the oracle, which only accepts
            proofs against a root it has stored.
          </Callout>
        </div>
      )}
    </Card>
  );
}

function ProofResult({
  values,
  check,
  mode,
  proofBytes,
  onChain,
  calldata,
}: {
  values: MembershipPublicValues;
  check: MembershipCheckResult;
  mode: "execute" | "groth16" | null;
  proofBytes: string | null;
  onChain: ReturnType<typeof useOnChainSet>;
  calldata: { verify: string; consume: string } | null;
}) {
  return (
    <>
      <Card
        title="Proof statement"
        subtitle="Decoded from the 224-byte public values."
        actions={
          check.ok ? (
            <StatusPill tone="good">✓ all fields match</StatusPill>
          ) : (
            <StatusPill tone="bad">✗ {check.failures.length} mismatch(es)</StatusPill>
          )
        }
      >
        <DefinitionList>
          <Row label="Your identity">
            <Hex value={values.nullifierHash} />
          </Row>
          <Row label="Set root">
            <Hex value={values.solventSetRoot} truncate />
          </Row>
          <Row label="Policy">
            <Hex value={values.policyId} truncate />
          </Row>
          <Row label="Epoch">{String(values.epoch)}</Row>
          <Row label="Chain ID">{String(values.chainId)}</Row>
          <Row label="Proven streak">≥ {String(values.minStreak)} epochs</Row>
          <Row label="Scope">
            <Hex value={values.scopeHash} truncate />
          </Row>
        </DefinitionList>

        <div className="mt-4">
          <Callout tone="info" title="About that identity">
            The nullifier hash is stable for this key and policy and unlinkable across policies.
            It is the same value a monitored-mode enrollment would produce, so relying protocols
            treat both modes identically.
          </Callout>
        </div>

        {!check.ok && (
          <div className="mt-4">
            <Callout tone="bad" title="These fields do not match what this browser verified">
              <ul className="mt-1 space-y-1">
                {check.failures.map((failure) => (
                  <li key={failure.field} className="font-mono text-xs break-all">
                    {failure.field}: expected {failure.expected}, got {failure.actual}
                  </li>
                ))}
              </ul>
              <p className="mt-2">
                The most common cause is proving against a stale set — re-run the command after
                reloading the set.
              </p>
            </Callout>
          </div>
        )}
      </Card>

      {mode === "execute" && (
        <Callout tone="warn" title="Emulated only — no proof bytes">
          The statement is valid, but <code className="font-mono">--execute-only</code> produces no
          Groth16 proof, so there is nothing to submit on-chain. Re-run without that flag to get a
          verifiable proof.
        </Callout>
      )}

      {mode === "groth16" && proofBytes && (
        <Card
          title="Submit to a relying protocol"
          subtitle="Hand these two values to the dApp, or call the oracle directly."
        >
          <div className="space-y-4">
            <Field label="proofBytes">
              <div className="flex items-start gap-2">
                <code className="font-mono text-xs break-all bg-gray-50 p-2 rounded flex-1 max-h-24 overflow-y-auto">
                  {proofBytes}
                </code>
                <CopyButton value={proofBytes} />
              </div>
            </Field>

            {calldata ? (
              <>
                <Field
                  label="verifyMembership calldata"
                  hint="View call — checks the proof without consuming the nullifier."
                >
                  <CodeBlock code={calldata.verify} />
                </Field>
                <Field
                  label="verifyAndConsume calldata"
                  hint="Enforces one use per key per policy across all callers."
                >
                  <CodeBlock code={calldata.consume} />
                </Field>
              </>
            ) : (
              <Callout tone="neutral">
                {onChain.setIndex === null
                  ? "Calldata needs the on-chain set index — configure VITE_ORACLE_ADDRESS and make sure the root is published."
                  : "Could not encode calldata from this output."}
              </Callout>
            )}

            {ORACLE_ADDRESS && (
              <p className="text-xs text-gray-500">
                Send to <span className="font-mono">{ORACLE_ADDRESS}</span>
                {onChain.chainId ? ` on chain ${onChain.chainId}` : ""}.
              </p>
            )}

            {/* verifyMembership reverts unless the proof's committed chainId
                equals block.chainid, so a mismatch here is a guaranteed
                failed call rather than a cosmetic difference. */}
            {onChain.chainId !== null && Number(values.chainId) !== onChain.chainId && (
              <Callout tone="bad" title="Chain mismatch — this call will revert">
                The proof commits to chain {String(values.chainId)}, but the oracle you would
                submit to is on chain {onChain.chainId}. Re-run the prove command with{" "}
                <code className="font-mono">--chain-id {onChain.chainId}</code>.
              </Callout>
            )}
          </div>
        </Card>
      )}
    </>
  );
}
