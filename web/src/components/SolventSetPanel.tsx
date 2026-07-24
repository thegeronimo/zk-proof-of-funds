import { useState } from "react";
import { useAccount, useConnect, useDisconnect } from "wagmi";
import type { SolventSetInfo, SolventSetEntryTuple, SolventSetPath } from "@zk-proof-of-funds/sdk";
import { computeSolventSetRoot, computeSolventSetPath } from "@zk-proof-of-funds/sdk";
import { apiClient } from "../services/apiClient";

/**
 * Privacy V2 solvent-set explorer.
 *
 * The solvent set is public data: every (address, streak) pair meeting the
 * policy threshold at the reference block. This panel downloads the whole
 * set and — if a wallet is connected — checks membership *locally*. The
 * connected address never leaves the browser; the agent only sees "someone
 * downloaded the set".
 */
export default function SolventSetPanel() {
  const { address, isConnected } = useAccount();
  const { connectors, connect } = useConnect();
  const { disconnect } = useDisconnect();

  const [policyId, setPolicyId] = useState("");
  const [info, setInfo] = useState<SolventSetInfo | null>(null);
  const [entryCount, setEntryCount] = useState<number | null>(null);
  const [rootVerified, setRootVerified] = useState<boolean | null>(null);
  const [membership, setMembership] = useState<
    | { checked: false }
    | { checked: true; path: SolventSetPath | null }
  >({ checked: false });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function loadSet() {
    if (!policyId) return;
    setError(null);
    setLoading(true);
    setInfo(null);
    setEntryCount(null);
    setRootVerified(null);
    setMembership({ checked: false });
    try {
      const { info: fetchedInfo, entries } = await apiClient.fetchAllSolventSetEntries(policyId);
      setInfo(fetchedInfo);
      setEntryCount(entries.length);

      // Rebuild the Merkle root locally — trust nothing you didn't hash.
      const localRoot = await computeSolventSetRoot(entries as SolventSetEntryTuple[]);
      const served = fetchedInfo.root.toLowerCase().replace(/^0x/, "");
      setRootVerified(localRoot === served);

      // Local membership check: the address never leaves the browser.
      if (address) {
        const path = await computeSolventSetPath(entries as SolventSetEntryTuple[], address);
        setMembership({ checked: true, path });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load solvent set");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold mb-2">Solvent Set (Privacy V2)</h1>
      <p className="text-gray-500 mb-6">
        The public set of all addresses meeting the policy threshold, with
        per-address streaks (consecutive solvent epochs). Membership is checked
        locally — your address never leaves the browser.
      </p>

      {/* Wallet connection */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        {isConnected ? (
          <div className="flex items-center justify-between">
            <div className="text-sm">
              <span className="text-gray-500">Connected: </span>
              <span className="font-mono">{address}</span>
            </div>
            <button
              onClick={() => disconnect()}
              className="px-3 py-1.5 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            >
              Disconnect
            </button>
          </div>
        ) : (
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-500">
              Connect a wallet to check your own membership locally (optional).
            </span>
            {connectors.slice(0, 1).map((connector) => (
              <button
                key={connector.uid}
                onClick={() => connect({ connector })}
                className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium text-sm"
              >
                Connect Wallet
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Policy input */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Policy ID
        </label>
        <input
          type="text"
          value={policyId}
          onChange={(e) => setPolicyId(e.target.value)}
          placeholder="Hex-encoded 32-byte policy ID"
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent text-sm font-mono mb-4"
        />
        <button
          onClick={loadSet}
          disabled={loading || !policyId}
          className="w-full px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed text-sm"
        >
          {loading ? "Downloading set..." : "Load Solvent Set"}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4">
          {error}
        </div>
      )}

      {/* Set metadata */}
      {info && (
        <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
          <h2 className="text-lg font-semibold mb-3">Current Epoch Set</h2>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <dt className="text-gray-500">Epoch</dt>
            <dd className="font-mono">{info.epoch}</dd>
            <dt className="text-gray-500">Reference block</dt>
            <dd className="font-mono">{info.block_number}</dd>
            <dt className="text-gray-500">Members</dt>
            <dd className="font-mono">{entryCount ?? info.member_count}</dd>
            <dt className="text-gray-500">Root</dt>
            <dd className="font-mono break-all">{info.root}</dd>
            <dt className="text-gray-500">Root verified locally</dt>
            <dd>
              {rootVerified === null ? (
                "—"
              ) : rootVerified ? (
                <span className="text-green-700">✓ rebuilt root matches</span>
              ) : (
                <span className="text-red-700">✗ MISMATCH — do not trust this set</span>
              )}
            </dd>
          </dl>
        </div>
      )}

      {/* Local membership result */}
      {membership.checked && (
        <div
          className={`rounded-lg border px-4 py-3 mb-6 ${
            membership.path
              ? "bg-green-50 border-green-200 text-green-800"
              : "bg-yellow-50 border-yellow-200 text-yellow-800"
          }`}
        >
          {membership.path ? (
            <div className="text-sm">
              <p className="font-semibold mb-1">
                Your address is in the solvent set ✓
              </p>
              <p>
                Streak: <span className="font-mono">{membership.path.streak}</span>{" "}
                consecutive epoch{membership.path.streak === 1 ? "" : "s"} · leaf index{" "}
                <span className="font-mono">{membership.path.leafIndex}</span>
              </p>
              <p className="mt-1 text-green-700">
                Use <span className="font-mono">zkpof-client prove</span> with your key to
                generate the membership proof — this page never sees your key.
              </p>
            </div>
          ) : (
            <p className="text-sm">
              Your address is not in this epoch&apos;s set (balance below the
              threshold at the reference block).
            </p>
          )}
        </div>
      )}

      <p className="text-xs text-gray-400">
        Checked entirely client-side: the full set is downloaded and hashed in
        your browser; no query about your address is ever sent to the agent.
      </p>
    </div>
  );
}
