/**
 * Identity — deriving a PLUME nullifier and enrolling with it (PRIVACY_V2.md §3).
 *
 * The nullifier is the user's stable, unlinkable identity for a policy:
 * `N = hash_to_curve(scope ‖ pk)·sk`, `memberId = SHA256(N)`. It is
 * deterministic, so one key yields exactly one identity per policy — a wallet
 * cannot mint several — and it is the *same* value the membership proof
 * commits to, which is why monitored mode and the solvent-set flow are
 * interchangeable to a relying protocol.
 *
 * Computing it needs the raw secret key, which browser wallets do not expose
 * (§3.3). This page therefore offers three paths, in order of preference:
 * the CLI, a wallet implementing ERC-7524, and — explicitly gated — a local
 * key entered here for development.
 */

import { useMemo, useState } from "react";
import { usePublicClient } from "wagmi";
import {
  buildEnrollV2Request,
  defaultScopeHash,
  deriveAddress,
  nullifierHash as hashNullifier,
  verifyNullifier,
} from "@zk-proof-of-funds/sdk/plume";
import { AGENT_PUBLIC_URL, apiClient } from "../services/apiClient";
import { usePolicySelection } from "../hooks/usePolicySelection";
import { ORACLE_ADDRESS, SOLVENT_SET_ORACLE_ABI, HAS_ORACLE } from "../config/contracts";
import PolicyPicker from "./PolicyPicker";
import {
  Button,
  Callout,
  Card,
  CodeBlock,
  DefinitionList,
  Field,
  Hex,
  PageHeader,
  Row,
  StatusPill,
  TextArea,
  TextInput,
  VerifiedPill,
} from "./ui";

/** The shape `zkpof-client nullifier` prints. */
interface NullifierJson {
  policy_id?: string;
  scope_hash?: string;
  public_key: string;
  nullifier: string;
  dleq_a: string;
  dleq_b: string;
  dleq_s: string;
  member_id?: string;
}

type Derived = {
  publicKey: string;
  nullifier: string;
  memberId: string;
  address: string | null;
  dleqValid: boolean;
  source: "cli" | "local-key";
  enrollBody: NullifierJson;
};

export default function IdentityPanel() {
  const { policyId, isValid } = usePolicySelection();
  const publicClient = usePublicClient();

  const [pasted, setPasted] = useState("");
  const [localKey, setLocalKey] = useState("");
  const [showLocalKey, setShowLocalKey] = useState(false);
  const [derived, setDerived] = useState<Derived | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [enrolling, setEnrolling] = useState(false);
  const [enrollResult, setEnrollResult] = useState<string | null>(null);

  const [nullifierUsed, setNullifierUsed] = useState<boolean | null>(null);
  const [walletProbe, setWalletProbe] = useState<string | null>(null);

  const scope = useMemo(() => {
    if (!isValid) return null;
    try {
      return `0x${defaultScopeHash(policyId).replace(/^0x/, "")}`;
    } catch {
      return null;
    }
  }, [policyId, isValid]);

  const nullifierCommand = [
    "zkpof-client nullifier",
    "  --sk <YOUR_32_BYTE_HEX_KEY>",
    `  --policy ${policyId}`,
  ].join(" \\\n");

  const enrollCommand = [
    "zkpof-client enroll",
    "  --sk <YOUR_32_BYTE_HEX_KEY>",
    `  --policy ${policyId}`,
    `  --agent ${AGENT_PUBLIC_URL}`,
  ].join(" \\\n");

  function acceptBundle(body: NullifierJson, source: Derived["source"]) {
    const scopeHash = body.scope_hash ?? scope;
    if (!scopeHash) throw new Error("No scope hash available for this policy");
    // Re-verify the DLEQ here rather than trusting the producer: it is the
    // proof that this nullifier is *the* one for this key and scope.
    const dleqValid = verifyNullifier(body.public_key, body.nullifier, scopeHash, {
      a: body.dleq_a,
      b: body.dleq_b,
      s: body.dleq_s,
    });
    let address: string | null = null;
    try {
      address = `0x${deriveAddress(body.public_key).replace(/^0x/, "")}`;
    } catch {
      address = null;
    }
    setDerived({
      publicKey: body.public_key,
      nullifier: body.nullifier,
      memberId: `0x${hashNullifier(body.nullifier).replace(/^0x/, "")}`,
      address,
      dleqValid,
      source,
      enrollBody: { ...body, scope_hash: scopeHash, policy_id: body.policy_id ?? policyId },
    });
    setNullifierUsed(null);
    setEnrollResult(null);
  }

  function loadPasted() {
    setError(null);
    setDerived(null);
    try {
      const parsed = JSON.parse(pasted) as NullifierJson;
      for (const key of ["public_key", "nullifier", "dleq_a", "dleq_b", "dleq_s"] as const) {
        if (typeof parsed[key] !== "string") {
          throw new Error(`Missing \`${key}\` — paste the output of \`zkpof-client nullifier\`.`);
        }
      }
      // A bundle is bound to the policy it was generated for. Enrolling it
      // under a different one would submit a nullifier scoped elsewhere, so
      // catch the mismatch here rather than letting the agent reject it.
      if (parsed.policy_id) {
        const pasted = parsed.policy_id.replace(/^0x/, "").toLowerCase();
        const selected = policyId.replace(/^0x/, "").toLowerCase();
        if (pasted !== selected) {
          throw new Error(
            `That bundle is for policy 0x${pasted}, but 0x${selected} is selected. Switch policy above, or re-run the command for this one.`
          );
        }
      }
      acceptBundle(parsed, "cli");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not read that output");
    }
  }

  function deriveLocally() {
    setError(null);
    setDerived(null);
    try {
      if (!scope) throw new Error("Select a valid policy first");
      acceptBundle(buildEnrollV2Request(localKey.trim(), policyId), "local-key");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Derivation failed");
    }
  }

  async function enroll() {
    if (!derived) return;
    setEnrolling(true);
    setEnrollResult(null);
    setError(null);
    try {
      const response = await apiClient.enrollV2({
        policy_id: policyId,
        scope_hash: derived.enrollBody.scope_hash,
        public_key: derived.publicKey,
        nullifier: derived.nullifier,
        dleq_a: derived.enrollBody.dleq_a,
        dleq_b: derived.enrollBody.dleq_b,
        dleq_s: derived.enrollBody.dleq_s,
      });
      setEnrollResult(
        `Enrolled as ${response.member_id} (effective epoch ${response.effective_epoch}).`
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Enrollment failed");
    } finally {
      setEnrolling(false);
    }
  }

  async function checkNullifierUsed() {
    if (!derived || !ORACLE_ADDRESS || !publicClient) return;
    setError(null);
    try {
      const used = await publicClient.readContract({
        address: ORACLE_ADDRESS,
        abi: SOLVENT_SET_ORACLE_ABI,
        functionName: "isNullifierUsed",
        args: [policyId as `0x${string}`, derived.memberId as `0x${string}`],
      });
      setNullifierUsed(used);
    } catch (err) {
      setError(err instanceof Error ? err.message : "On-chain read failed");
    }
  }

  async function probeWallet() {
    setWalletProbe(null);
    const ethereum = (window as { ethereum?: { request: (args: unknown) => Promise<unknown> } })
      .ethereum;
    if (!ethereum) {
      setWalletProbe("No injected wallet found.");
      return;
    }
    try {
      await ethereum.request({ method: "eth_getPlumeSignature", params: [] });
      setWalletProbe("This wallet responded to eth_getPlumeSignature.");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setWalletProbe(`Not supported by this wallet: ${message}`);
    }
  }

  return (
    <div className="max-w-3xl mx-auto">
      <PageHeader title="Identity">
        Your nullifier is a deterministic, scope-bound identity derived from your key. One key
        gives exactly one identity per scope. When two policies use <em>different</em> scopes,
        their nullifier values alone do not link — but policies can deliberately share a scope,
        and timing, an unusual streak, or network metadata can still correlate uses.
      </PageHeader>

      <div className="space-y-6">
        <Card title="Policy">
          <PolicyPicker compact />
          {scope && (
            <div className="mt-4">
              <DefinitionList>
                <Row label="Scope hash">
                  <Hex value={scope} />
                </Row>
              </DefinitionList>
              <p className="text-xs text-gray-500 mt-2">
                SHA256("zkpof-scope-v1:" ‖ policy_id) — the message the nullifier binds to. Policies
                that deliberately share an identity namespace override it on-chain.
              </p>
            </div>
          )}
        </Card>

        <Card
          title="Derive your nullifier"
          subtitle="Needs raw key access, so it happens outside the browser by default."
        >
          <div className="space-y-5">
            <div>
              <h3 className="text-sm font-semibold text-gray-900 mb-2">
                1. Run locally (recommended)
              </h3>
              <CodeBlock code={nullifierCommand} language="bash" />
              <div className="mt-3">
                <Field label="Paste the JSON it prints">
                  <TextArea
                    value={pasted}
                    onChange={setPasted}
                    rows={6}
                    placeholder={'{\n  "public_key": "…",\n  "nullifier": "…",\n  "dleq_a": "…"\n}'}
                  />
                </Field>
                <div className="mt-3">
                  <Button onClick={loadPasted} disabled={!pasted.trim()} full>
                    Load and verify
                  </Button>
                </div>
              </div>
            </div>

            <div className="border-t border-gray-200 pt-5">
              <h3 className="text-sm font-semibold text-gray-900 mb-2">2. Wallet-native (ERC-7524)</h3>
              <p className="text-sm text-gray-500 mb-3">
                Our nullifier matches ERC-7524 exactly, so a wallet implementing{" "}
                <code className="font-mono text-xs">eth_getPlumeSignature</code> would yield the
                same identity. Consuming a wallet-produced <em>proof</em> additionally needs the
                ERC's own challenge encoding, which is not implemented yet.
              </p>
              <Button onClick={probeWallet} variant="ghost" size="sm">
                Test this wallet
              </Button>
              {walletProbe && (
                <p className="text-xs text-gray-600 mt-2 font-mono break-all">{walletProbe}</p>
              )}
            </div>

            <div className="border-t border-gray-200 pt-5">
              <h3 className="text-sm font-semibold text-gray-900 mb-2">3. Local key (development)</h3>
              {!showLocalKey ? (
                <Button onClick={() => setShowLocalKey(true)} variant="ghost" size="sm">
                  Enter a key in the browser
                </Button>
              ) : (
                <div className="space-y-3">
                  <Callout tone="bad" title="Only for throwaway development keys">
                    Never paste a key that holds real funds into any web page — including this one.
                    The key stays in this tab and only public values are sent to the agent, but
                    treating a browser as a signer is a habit worth not forming. The CLI above does
                    the same work without the risk.
                  </Callout>
                  <Field label="Secret key" hint="32-byte hex. Not stored, not transmitted.">
                    <TextInput
                      value={localKey}
                      onChange={setLocalKey}
                      placeholder="0x…"
                      type="password"
                      mono
                    />
                  </Field>
                  <Button onClick={deriveLocally} disabled={!localKey.trim() || !isValid} full>
                    Derive in browser
                  </Button>
                </div>
              )}
            </div>
          </div>
          {error && (
            <div className="mt-4">
              <Callout tone="bad">{error}</Callout>
            </div>
          )}
        </Card>

        {derived && (
          <Card
            title="Your identity for this policy"
            actions={
              <VerifiedPill
                state={derived.dleqValid}
                verifiedLabel="DLEQ verified"
                failedLabel="DLEQ INVALID"
              />
            }
          >
            <DefinitionList>
              <Row label="Member ID">
                <Hex value={derived.memberId} />
              </Row>
              <Row label="Nullifier">
                <Hex value={derived.nullifier} truncate />
              </Row>
              <Row label="Public key">
                <Hex value={derived.publicKey} truncate />
              </Row>
              <Row label="Address">
                {derived.address ? <Hex value={derived.address} /> : "—"}
              </Row>
              <Row label="Derived">
                <StatusPill>{derived.source === "cli" ? "via zkpof-client" : "in browser"}</StatusPill>
              </Row>
            </DefinitionList>

            {!derived.dleqValid && (
              <div className="mt-4">
                <Callout tone="bad" title="The DLEQ proof does not verify">
                  This nullifier is not provably the right one for that public key and scope. The
                  agent will reject it. Check that the policy selected here matches the one the
                  bundle was produced for.
                </Callout>
              </div>
            )}

            <div className="mt-4">
              <Callout tone="info">
                This member ID is exactly what a membership proof commits to as its nullifier hash.
                Enrolling is optional — the solvent-set flow needs no enrollment at all.
              </Callout>
            </div>

            <div className="mt-4 flex flex-wrap gap-2">
              <Button onClick={enroll} disabled={enrolling || !derived.dleqValid}>
                {enrolling ? "Enrolling…" : "Enroll with the agent"}
              </Button>
              {HAS_ORACLE && (
                <Button onClick={checkNullifierUsed} variant="ghost">
                  Check if consumed on-chain
                </Button>
              )}
            </div>

            {enrollResult && (
              <div className="mt-4">
                <Callout tone="good" title="Enrolled">
                  {enrollResult}
                </Callout>
              </div>
            )}
            {nullifierUsed !== null && (
              <div className="mt-4">
                <Callout tone={nullifierUsed ? "warn" : "good"}>
                  {nullifierUsed
                    ? "This nullifier has already been consumed for this policy — verifyAndConsume will revert."
                    : "Not yet consumed: verifyAndConsume will succeed for this policy."}
                </Callout>
              </div>
            )}
          </Card>
        )}

        <Card
          title="Enroll in one step"
          subtitle="If you would rather not paste anything back, the CLI can enroll directly."
        >
          <CodeBlock code={enrollCommand} language="bash" />
        </Card>
      </div>
    </div>
  );
}
