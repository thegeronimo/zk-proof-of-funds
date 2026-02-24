import { useState } from "react";
import { useAccount, useConnect, useDisconnect } from "wagmi";
import type { MemberStatus, MerkleProofData } from "@zk-proof-of-funds/sdk";
import { apiClient } from "../services/apiClient";

export default function Dashboard() {
  const { address, isConnected } = useAccount();
  const { connectors, connect } = useConnect();
  const { disconnect } = useDisconnect();

  const [policyId, setPolicyId] = useState("");
  const [memberId, setMemberId] = useState("");
  const [status, setStatus] = useState<MemberStatus | null>(null);
  const [proof, setProof] = useState<MerkleProofData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Submit Proof state
  const [proofSubmitting, setProofSubmitting] = useState(false);
  const [proofResult, setProofResult] = useState<{
    status: string;
    balance_wei: string;
    epoch: number;
    block_number: number;
  } | null>(null);
  const [blockNumber, setBlockNumber] = useState("");

  async function fetchStatus() {
    if (!policyId || !memberId) return;
    setError(null);
    setLoading(true);
    try {
      const result = await apiClient.getMemberStatus(policyId, memberId);
      setStatus(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch status");
    } finally {
      setLoading(false);
    }
  }

  async function fetchProof() {
    if (!policyId || !memberId) return;
    setError(null);
    setLoading(true);
    try {
      const result = await apiClient.getMemberProof(policyId, memberId);
      setProof(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch proof");
    } finally {
      setLoading(false);
    }
  }

  async function submitProof() {
    if (!policyId || !memberId || !address || !window.ethereum) return;
    setError(null);
    setProofSubmitting(true);
    setProofResult(null);
    try {
      // 1. Determine block number — use user-provided or fetch latest
      let targetBlock: string;
      if (blockNumber) {
        targetBlock = "0x" + parseInt(blockNumber, 10).toString(16);
      } else {
        const blockHex = await window.ethereum.request({
          method: "eth_blockNumber",
          params: [],
        });
        targetBlock = blockHex as string;
      }
      const blockNum = parseInt(targetBlock, 16);

      // 2. Call eth_getProof via the connected wallet's provider
      const proofResponse = await window.ethereum.request({
        method: "eth_getProof",
        params: [address, [], targetBlock],
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const accountProof = (proofResponse as any).accountProof as string[];

      // 3. Submit to agent — wallet_address is used transiently for MPT verification only
      const result = await apiClient.submitProof(policyId, memberId, {
        wallet_address: address,
        proof_nodes: accountProof,
        block_number: blockNum,
      });

      setProofResult({
        status: result.status,
        balance_wei: result.balance_wei,
        epoch: result.epoch,
        block_number: result.block_number,
      });
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to submit proof"
      );
    } finally {
      setProofSubmitting(false);
    }
  }

  function copyProofCalldata() {
    if (!proof) return;
    const calldata = {
      policyId: proof.policy_id,
      memberId: proof.member_id,
      status: proof.status,
      epoch: proof.epoch,
      merkleProof: proof.merkle_proof,
      leafIndex: proof.leaf_index,
      rootIndex: 0,
    };
    navigator.clipboard.writeText(JSON.stringify(calldata, null, 2));
  }

  const statusColor = {
    solvent: "text-green-700 bg-green-50 border-green-200",
    insolvent: "text-red-700 bg-red-50 border-red-200",
    pending: "text-yellow-700 bg-yellow-50 border-yellow-200",
    fetch_failed: "text-gray-700 bg-gray-50 border-gray-200",
  };

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold mb-2">Member Dashboard</h1>
      <p className="text-gray-500 mb-6">
        Check your solvency status, submit proofs, and retrieve Merkle proofs
        for on-chain verification.
      </p>

      {/* Input form */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <div className="grid grid-cols-1 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Policy ID
            </label>
            <input
              type="text"
              value={policyId}
              onChange={(e) => setPolicyId(e.target.value)}
              placeholder="Hex-encoded 32-byte policy ID"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent text-sm font-mono"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Member ID
            </label>
            <input
              type="text"
              value={memberId}
              onChange={(e) => setMemberId(e.target.value)}
              placeholder="Hex-encoded 32-byte member ID"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent text-sm font-mono"
            />
          </div>
          <div className="flex gap-3">
            <button
              onClick={fetchStatus}
              disabled={loading || !policyId || !memberId}
              className="flex-1 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed text-sm"
            >
              {loading ? "Loading..." : "Fetch Status"}
            </button>
            <button
              onClick={fetchProof}
              disabled={loading || !policyId || !memberId}
              className="flex-1 px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed text-sm"
            >
              {loading ? "Loading..." : "Fetch Proof"}
            </button>
          </div>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4">
          {error}
        </div>
      )}

      {/* Submit Proof section */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <h2 className="text-lg font-semibold mb-2">Submit Solvency Proof</h2>
        <p className="text-sm text-gray-500 mb-4">
          Fetch an EIP-1186 state proof from your Ethereum node and submit it to
          the agent. Your wallet address is used only for MPT verification and is
          never stored.
        </p>

        {!isConnected ? (
          <div>
            <p className="text-sm text-gray-500 mb-3">
              Connect your wallet to submit a proof:
            </p>
            <div className="flex flex-col gap-2">
              {connectors.map((connector) => (
                <button
                  key={connector.uid}
                  onClick={() => connect({ connector })}
                  className="w-full px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium text-sm"
                >
                  {connector.name}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
              <span className="text-sm text-green-700">
                Connected: {address?.slice(0, 6)}...{address?.slice(-4)}
              </span>
              <button
                onClick={() => disconnect()}
                className="text-sm text-gray-500 hover:text-gray-700"
              >
                Disconnect
              </button>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Block Number (optional — uses latest if empty)
              </label>
              <input
                type="text"
                value={blockNumber}
                onChange={(e) => setBlockNumber(e.target.value)}
                placeholder="e.g., 19500000"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent text-sm font-mono"
              />
            </div>
            <button
              onClick={submitProof}
              disabled={proofSubmitting || !policyId || !memberId}
              className="w-full px-4 py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {proofSubmitting
                ? "Fetching proof & submitting..."
                : "Submit Solvency Proof"}
            </button>
          </div>
        )}

        {/* Proof submission result */}
        {proofResult && (
          <div className="mt-4 p-4 bg-gray-50 rounded-lg">
            <h3 className="text-sm font-semibold mb-2">Proof Verified</h3>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-xs text-gray-500">Status</p>
                <span
                  className={`inline-block mt-1 px-2 py-0.5 rounded-full text-xs font-medium border ${
                    proofResult.status === "solvent"
                      ? "text-green-700 bg-green-50 border-green-200"
                      : "text-red-700 bg-red-50 border-red-200"
                  }`}
                >
                  {proofResult.status}
                </span>
              </div>
              <div>
                <p className="text-xs text-gray-500">Balance</p>
                <p className="text-sm font-mono mt-1">
                  {proofResult.balance_wei} wei
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500">Epoch</p>
                <p className="text-sm font-mono mt-1">{proofResult.epoch}</p>
              </div>
              <div>
                <p className="text-xs text-gray-500">Block</p>
                <p className="text-sm font-mono mt-1">
                  {proofResult.block_number}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Status display */}
      {status && (
        <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">Solvency Status</h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm text-gray-500">Status</p>
              <span
                className={`inline-block mt-1 px-3 py-1 rounded-full text-sm font-medium border ${
                  statusColor[status.status] ?? statusColor.pending
                }`}
              >
                {status.status}
              </span>
            </div>
            <div>
              <p className="text-sm text-gray-500">Last Balance</p>
              <p className="text-sm font-mono mt-1">
                {status.last_balance_wei} wei
              </p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Last Checked Block</p>
              <p className="text-sm font-mono mt-1">
                {status.last_checked_block}
              </p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Effective Epoch</p>
              <p className="text-sm font-mono mt-1">
                {status.effective_epoch}
              </p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Enrolled At</p>
              <p className="text-sm font-mono mt-1">
                {new Date(status.enrolled_at * 1000).toLocaleString()}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Proof display */}
      {proof && (
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Merkle Proof</h2>
            <button
              onClick={copyProofCalldata}
              className="px-3 py-1 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors text-sm"
            >
              Copy Calldata
            </button>
          </div>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-500">Epoch</p>
                <p className="text-sm font-mono">{proof.epoch}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Status</p>
                <p className="text-sm font-mono">
                  {proof.status === 1 ? "Solvent" : "Insolvent"}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Leaf Index</p>
                <p className="text-sm font-mono">{proof.leaf_index}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Block Number</p>
                <p className="text-sm font-mono">{proof.block_number}</p>
              </div>
            </div>
            <div>
              <p className="text-sm text-gray-500">Root</p>
              <code className="text-xs font-mono break-all bg-gray-50 block p-2 rounded mt-1">
                {proof.root}
              </code>
            </div>
            <div>
              <p className="text-sm text-gray-500">
                Proof Path ({proof.merkle_proof.length} hashes)
              </p>
              <div className="bg-gray-50 rounded p-2 mt-1 max-h-48 overflow-y-auto">
                {proof.merkle_proof.map((hash, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <span className="text-xs text-gray-400 w-6">{i}</span>
                    <code className="text-xs font-mono break-all">{hash}</code>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
