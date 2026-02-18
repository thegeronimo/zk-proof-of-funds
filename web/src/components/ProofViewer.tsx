import { useState } from "react";

interface ProofInput {
  memberId: string;
  status: number;
  epoch: number;
  leafIndex: number;
  merkleProof: string[];
  root: string;
}

export default function ProofViewer() {
  const [jsonInput, setJsonInput] = useState("");
  const [proofData, setProofData] = useState<ProofInput | null>(null);
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
    <div className="max-w-3xl mx-auto">
      <h1 className="text-2xl font-bold mb-2">Proof Viewer</h1>
      <p className="text-gray-500 mb-6">
        Visualize a Merkle inclusion proof. Paste the JSON response from{" "}
        <code className="text-sm bg-gray-100 px-1 rounded">
          GET /proof/:policyId/:memberId
        </code>
        .
      </p>

      {/* JSON input */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Proof JSON
        </label>
        <textarea
          value={jsonInput}
          onChange={(e) => setJsonInput(e.target.value)}
          placeholder='{"member_id": "...", "status": 1, "epoch": 42, "merkle_proof": [...], "root": "..."}'
          rows={6}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent text-sm font-mono"
        />
        {parseError && (
          <p className="text-red-600 text-sm mt-2">{parseError}</p>
        )}
        <button
          onClick={parseProof}
          disabled={!jsonInput.trim()}
          className="mt-3 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium disabled:opacity-50 text-sm"
        >
          Visualize
        </button>
      </div>

      {/* Visualization */}
      {proofData && (
        <div className="space-y-6">
          {/* Summary */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-lg font-semibold mb-4">Proof Summary</h2>
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center p-3 bg-gray-50 rounded-lg">
                <p className="text-2xl font-bold text-primary-600">
                  {treeDepth}
                </p>
                <p className="text-xs text-gray-500">Tree Depth</p>
              </div>
              <div className="text-center p-3 bg-gray-50 rounded-lg">
                <p className="text-2xl font-bold text-primary-600">
                  ~{Math.pow(2, treeDepth)}
                </p>
                <p className="text-xs text-gray-500">Max Tree Size</p>
              </div>
              <div className="text-center p-3 bg-gray-50 rounded-lg">
                <p className="text-2xl font-bold text-primary-600">
                  ~{gasEstimate.toLocaleString()}
                </p>
                <p className="text-xs text-gray-500">Gas Estimate</p>
              </div>
            </div>
          </div>

          {/* Tree visualization (ASCII) */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-lg font-semibold mb-4">
              Merkle Path Visualization
            </h2>
            <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm overflow-x-auto">
              <TreeAscii
                leafIndex={proofData.leafIndex}
                proof={proofData.merkleProof}
                root={proofData.root}
                status={proofData.status}
              />
            </div>
          </div>

          {/* On-chain verification code */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-lg font-semibold mb-4">
              Solidity Verification Call
            </h2>
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
          </div>
        </div>
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
    const indent = "  ".repeat(1);
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

  lines.push(
    `  Leaf[${leafIndex}]: status=${status === 1 ? "SOLVENT" : "INSOLVENT"}`
  );

  return <>{lines.join("\n")}</>;
}
