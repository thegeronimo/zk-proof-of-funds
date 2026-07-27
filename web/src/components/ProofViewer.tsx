/**
 * Proof inspector — the relying party's view.
 *
 * A dApp receives `(proofBytes, publicValues)` from a user with no other
 * context and has to decide whether to honour it. This page decodes the
 * statement so that decision is made on visible facts, and lets the operator's
 * side check a V1 Merkle proof too. The two protocols are kept in separate
 * modes because they attest to genuinely different things.
 */

import { useState } from "react";
import { usePublicClient } from "wagmi";
import {
  decodeMembershipPublicValues,
  checkMembershipPublicValues,
  type MembershipPublicValues,
  type MembershipCheckResult,
} from "@zk-proof-of-funds/sdk";
import {
  ORACLE_ADDRESS,
  ORACLE_CHAIN_ID,
  SOLVENT_SET_ORACLE_ABI,
} from "../config/contracts";
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

type Mode = "v2" | "v1";

export default function ProofViewer() {
  const [mode, setMode] = useState<Mode>("v2");

  return (
    <div className="max-w-3xl mx-auto">
      <PageHeader title="Inspect a proof">
        Decode what a proof actually claims before acting on it.
      </PageHeader>

      <div className="flex gap-1 mb-6 bg-gray-100 p-1 rounded-lg w-fit">
        {(
          [
            ["v2", "Membership (Privacy V2)"],
            ["v1", "Merkle proof (monitored mode)"],
          ] as [Mode, string][]
        ).map(([value, label]) => (
          <button
            key={value}
            onClick={() => setMode(value)}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              mode === value ? "bg-white shadow-sm text-gray-900" : "text-gray-600 hover:text-gray-900"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {mode === "v2" ? <MembershipInspector /> : <MerkleInspector />}
    </div>
  );
}

// ── Privacy V2 ──────────────────────────────────────────────────────────────

/** Outcome of asking the oracle to verify the proof for real. */
interface VerificationResult {
  /** True only when `verifyMembership` returned without reverting. */
  valid: boolean;
  /** The revert reason, when it reverted. */
  reason?: string;
  nullifierHash?: string;
  minStreak?: bigint;
}

function MembershipInspector() {
  const [input, setInput] = useState("");
  const [proofInput, setProofInput] = useState("");
  const [values, setValues] = useState<MembershipPublicValues | null>(null);
  const [error, setError] = useState<string | null>(null);

  // What the relying party independently requires.
  const [expectedPolicy, setExpectedPolicy] = useState("");
  const [expectedChain, setExpectedChain] = useState("");
  const [requiredStreak, setRequiredStreak] = useState("");
  const [setIndex, setSetIndex] = useState("");
  const [check, setCheck] = useState<MembershipCheckResult | null>(null);
  const [verification, setVerification] = useState<VerificationResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  const publicClient = usePublicClient(
    ORACLE_CHAIN_ID ? { chainId: ORACLE_CHAIN_ID } : undefined
  );

  /**
   * Ask the oracle to verify the proof, for real.
   *
   * Decoding tells you what a proof *claims*; only this call tells you the
   * Groth16 proof is valid, the root is one the oracle stored, the entry is
   * live and unrevoked, and the presentation context matches. The screen
   * previously showed a green "meets your requirements" state for a decoded
   * blob with no valid proof behind it at all (review §3.8).
   */
  async function verifyOnChain(decoded: MembershipPublicValues) {
    if (!publicClient || !ORACLE_ADDRESS) return;
    const index = setIndex.trim();
    if (!index) {
      setVerification({
        valid: false,
        reason: "Enter the on-chain set index this proof targets.",
      });
      return;
    }
    setVerifying(true);
    setVerification(null);
    try {
      const result = await publicClient.readContract({
        address: ORACLE_ADDRESS,
        abi: SOLVENT_SET_ORACLE_ABI,
        functionName: "verifyMembership",
        args: [
          decoded.policyId as `0x${string}`,
          BigInt(index),
          `0x${input.trim().replace(/^0x/, "")}` as `0x${string}`,
          `0x${proofInput.trim().replace(/^0x/, "")}` as `0x${string}`,
        ],
      });
      const [nullifierHash, minStreak] = result as [string, bigint];
      setVerification({ valid: true, nullifierHash, minStreak });
    } catch (err) {
      setVerification({
        valid: false,
        reason: err instanceof Error ? err.message : "The oracle rejected this proof.",
      });
    } finally {
      setVerifying(false);
    }
  }

  function decode() {
    setError(null);
    setValues(null);
    setCheck(null);
    try {
      // Accept either the raw hex blob or the whole zkpof-client JSON object.
      const trimmed = input.trim();
      let blob = trimmed;
      if (trimmed.startsWith("{")) {
        const parsed = JSON.parse(trimmed) as Record<string, unknown>;
        if (typeof parsed.public_values_abi !== "string") {
          throw new Error("JSON has no `public_values_abi` field.");
        }
        blob = parsed.public_values_abi;
      }
      const decoded = decodeMembershipPublicValues(blob);
      setValues(decoded);
      setVerification(null);
      // The JSON form carries the proof bytes too; keep them for the real
      // verification call.
      if (trimmed.startsWith("{")) {
        const parsed = JSON.parse(trimmed) as Record<string, unknown>;
        if (typeof parsed.proof_bytes === "string") setProofInput(parsed.proof_bytes);
      }
      setCheck(
        checkMembershipPublicValues(decoded, {
          policyId: expectedPolicy.trim() || undefined,
          chainId: expectedChain.trim() ? Number(expectedChain) : undefined,
          requiredMinStreak: requiredStreak.trim() ? Number(requiredStreak) : undefined,
        })
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not decode");
    }
  }

  return (
    <div className="space-y-6">
      <Card
        title="Public values"
        subtitle="The 448-byte blob, or the whole JSON object from zkpof-client prove."
      >
        <TextArea
          value={input}
          onChange={setInput}
          rows={6}
          placeholder="0x… (448 bytes) or the zkpof-client JSON"
        />
        <div className="mt-3">
          <Button onClick={decode} disabled={!input.trim()} full>
            Decode
          </Button>
        </div>
        {error && <p className="text-sm text-red-600 mt-3">{error}</p>}
      </Card>

      <Card
        title="Your requirements"
        subtitle="Optional — anything you fill in is checked against the statement."
      >
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Policy ID">
            <TextInput value={expectedPolicy} onChange={setExpectedPolicy} placeholder="0x…" mono />
          </Field>
          <Field label="Chain ID">
            <TextInput value={expectedChain} onChange={setExpectedChain} placeholder="1" mono />
          </Field>
          <Field label="Minimum streak">
            <TextInput value={requiredStreak} onChange={setRequiredStreak} placeholder="3" mono />
          </Field>
        </div>
      </Card>

      {values && (
        <Card
          title="What this proof claims"
          actions={
            check?.ok ? (
              <StatusPill tone="good">✓ meets your requirements</StatusPill>
            ) : check && check.failures.length > 0 ? (
              <StatusPill tone="bad">✗ does not meet them</StatusPill>
            ) : null
          }
        >
          <DefinitionList>
            <Row label="Prover identity">
              <Hex value={values.nullifierHash} />
            </Row>
            <Row label="Solvent-set root">
              <Hex value={values.solventSetRoot} truncate />
            </Row>
            <Row label="Policy">
              <Hex value={values.policyId} truncate />
            </Row>
            <Row label="Epoch">{String(values.epoch)}</Row>
            <Row label="Chain ID">{String(values.chainId)}</Row>
            <Row label="Streak proven">≥ {String(values.minStreak)} epochs</Row>
            <Row label="Scope">
              <Hex value={values.scopeHash} truncate />
            </Row>
          </DefinitionList>

          {check && check.failures.length > 0 && (
            <div className="mt-4">
              <Callout tone="bad" title="Mismatches">
                <ul className="mt-1 space-y-1">
                  {check.failures.map((failure) => (
                    <li key={failure.field} className="font-mono text-xs break-all">
                      {failure.field}: expected {failure.expected}, got {failure.actual}
                    </li>
                  ))}
                </ul>
              </Callout>
            </div>
          )}

          <div className="mt-6 border-t border-slate-200 pt-4">
            <h4 className="font-medium mb-2">Cryptographic verification</h4>
            {!ORACLE_ADDRESS ? (
              <Callout tone="warn" title="No oracle configured">
                Set <code className="font-mono">VITE_ORACLE_ADDRESS</code> to check this proof
                against the chain. Everything above is only a decode of what the blob claims.
              </Callout>
            ) : (
              <>
                <Field label="Proof bytes" hint="The Groth16 proof from zkpof-client prove.">
                  <TextArea
                    value={proofInput}
                    onChange={setProofInput}
                    rows={3}
                    placeholder="0x…"
                  />
                </Field>
                <Field
                  label="On-chain set index"
                  hint="Which stored entry this proof targets (getSetCount − 1 for the latest)."
                >
                  <TextInput value={setIndex} onChange={setSetIndex} placeholder="0" />
                </Field>
                <Button
                  onClick={() => values && verifyOnChain(values)}
                  disabled={verifying || !proofInput.trim()}
                  full
                >
                  {verifying ? "Verifying…" : "Verify against the oracle"}
                </Button>

                {verification && (
                  <div className="mt-3">
                    {verification.valid ? (
                      <Callout tone="good" title="✓ Cryptographically valid">
                        The oracle accepted this proof: the Groth16 proof verifies, the root is
                        one it stored, the entry is live and unrevoked, and the presentation
                        context matches this verifier.
                        <div className="mt-2 font-mono text-xs break-all">
                          nullifier: {verification.nullifierHash}
                          <br />
                          minStreak: {String(verification.minStreak)}
                        </div>
                      </Callout>
                    ) : (
                      <Callout tone="bad" title="✗ The oracle rejected this proof">
                        <span className="font-mono text-xs break-all">{verification.reason}</span>
                      </Callout>
                    )}
                  </div>
                )}
              </>
            )}
          </div>

          {!verification?.valid && (
            <div className="mt-4">
              <Callout tone="warn" title="Decoding is not verification">
                Everything above is what the blob <em>claims</em>. Until the oracle accepts it,
                treat it as unverified — a well-formed blob can be fabricated with no valid proof
                behind it.
              </Callout>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

// ── Monitored mode (V1) ─────────────────────────────────────────────────────

interface MerkleProofInput {
  memberId: string;
  status: number;
  epoch: number;
  leafIndex: number;
  merkleProof: string[];
  root: string;
}

function MerkleInspector() {
  const [jsonInput, setJsonInput] = useState("");
  const [proofData, setProofData] = useState<MerkleProofInput | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  function parseProof() {
    setParseError(null);
    try {
      const data = JSON.parse(jsonInput);
      setProofData({
        memberId: data.member_id || data.memberId || "",
        status: data.status ?? 1,
        epoch: data.epoch ?? 0,
        leafIndex: data.leaf_index ?? data.leafIndex ?? 0,
        merkleProof: data.merkle_proof || data.merkleProof || [],
        root: data.root || "",
      });
    } catch {
      setParseError("Invalid JSON. Paste the proof response from the API.");
    }
  }

  const treeDepth = proofData ? proofData.merkleProof.length : 0;
  const gasEstimate = treeDepth * 84 + 5000; // ~84 gas per SHA-256 level + base

  return (
    <div className="space-y-6">
      <Card
        title="Merkle proof JSON"
        subtitle="The response from GET /proof/:policyId/:memberId."
      >
        <TextArea
          value={jsonInput}
          onChange={setJsonInput}
          rows={6}
          placeholder='{"member_id": "…", "status": 1, "epoch": 42, "merkle_proof": [...], "root": "…"}'
        />
        {parseError && <p className="text-red-600 text-sm mt-2">{parseError}</p>}
        <div className="mt-3">
          <Button onClick={parseProof} disabled={!jsonInput.trim()} full>
            Visualize
          </Button>
        </div>
      </Card>

      {proofData && (
        <>
          <Card title="Proof summary">
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center p-3 bg-gray-50 rounded-lg">
                <p className="text-2xl font-bold text-primary-600">{treeDepth}</p>
                <p className="text-xs text-gray-500">Tree depth</p>
              </div>
              <div className="text-center p-3 bg-gray-50 rounded-lg">
                <p className="text-2xl font-bold text-primary-600">~{Math.pow(2, treeDepth)}</p>
                <p className="text-xs text-gray-500">Max tree size</p>
              </div>
              <div className="text-center p-3 bg-gray-50 rounded-lg">
                <p className="text-2xl font-bold text-primary-600">
                  ~{gasEstimate.toLocaleString()}
                </p>
                <p className="text-xs text-gray-500">Gas estimate</p>
              </div>
            </div>
          </Card>

          <Card title="Merkle path">
            <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm overflow-x-auto whitespace-pre">
              <TreeAscii
                leafIndex={proofData.leafIndex}
                proof={proofData.merkleProof}
                root={proofData.root}
                status={proofData.status}
              />
            </div>
          </Card>

          <Card title="Solidity verification call">
            <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg text-xs overflow-x-auto">
              {`oracle.verifyMember(
    policyId,
    bytes32(0x${proofData.memberId.replace("0x", "").slice(0, 16)}...),
    ${proofData.status},     // status
    ${proofData.epoch},      // epoch
    merkleProof,             // ${treeDepth} hashes
    ${proofData.leafIndex},  // leafIndex
    0                        // rootIndex (latest)
);`}
            </pre>
          </Card>
        </>
      )}
    </div>
  );
}

/** ASCII tree rendering of the Merkle proof path. */
function TreeAscii({
  leafIndex,
  proof,
  root,
  status,
}: {
  leafIndex: number;
  proof: string[];
  root: string;
  status: number;
}) {
  const shortHash = (h: string) => h.replace("0x", "").slice(0, 12) + "...";
  const depth = proof.length;

  const lines: string[] = [];
  lines.push(`  Root: [${shortHash(root)}]`);
  lines.push(`  |`);

  let idx = leafIndex;
  for (let i = depth - 1; i >= 0; i--) {
    const level = depth - i;
    const indent = "  ";
    const isLeft = idx % 2 === 0;
    const sibling = shortHash(proof[i]);

    if (isLeft) {
      lines.push(`${indent}Level ${level}: [computed] --- [${sibling}]`);
      lines.push(`${indent}           (left)         (sibling)`);
    } else {
      lines.push(`${indent}Level ${level}: [${sibling}] --- [computed]`);
      lines.push(`${indent}           (sibling)       (right)`);
    }
    lines.push(`${indent}  |`);
    idx = Math.floor(idx / 2);
  }

  lines.push(`  Leaf[${leafIndex}]: status=${status === 1 ? "SOLVENT" : "INSOLVENT"}`);

  return <>{lines.join("\n")}</>;
}
