import { useState } from "react";
import { useAccount, useConnect, useDisconnect, useSignMessage } from "wagmi";
import { buildEnrollmentMessage } from "@zk-proof-of-funds/sdk";
import { apiClient } from "../services/apiClient";

type Step = "connect" | "configure" | "sign" | "enroll" | "done";

export default function EnrollmentFlow() {
  const { address, isConnected } = useAccount();
  const { connectors, connect } = useConnect();
  const { disconnect } = useDisconnect();
  const { signMessageAsync } = useSignMessage();

  const [step, setStep] = useState<Step>(isConnected ? "configure" : "connect");
  const [policyId, setPolicyId] = useState("");
  const [scope, setScope] = useState("default");
  const [nonce, setNonce] = useState(() => Math.floor(Math.random() * 1_000_000).toString());
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [memberId, setMemberId] = useState<string | null>(null);
  const [signature, setSignature] = useState<string | null>(null);

  const message = buildEnrollmentMessage(scope, nonce);

  async function handleSign() {
    setError(null);
    setLoading(true);
    try {
      const sig = await signMessageAsync({ message });
      setSignature(sig);
      setStep("enroll");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Signing failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleEnroll() {
    if (!signature || !address) return;
    setError(null);
    setLoading(true);
    try {
      const result = await apiClient.enroll({
        policy_id: policyId,
        wallet_address: address,
        signature,
        signed_message: message,
      });
      setMemberId(result.member_id);
      setStep("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Enrollment failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-lg mx-auto">
      <h1 className="text-2xl font-bold mb-2">Enrollment</h1>
      <p className="text-gray-500 mb-6">
        Prove wallet control and enroll in a solvency policy. You only need to
        do this once.
      </p>

      {/* Step indicators */}
      <div className="flex items-center gap-2 mb-8">
        {(["connect", "configure", "sign", "enroll", "done"] as Step[]).map(
          (s, i) => (
            <div key={s} className="flex items-center gap-2">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                  step === s
                    ? "bg-primary-600 text-white"
                    : i <
                      ["connect", "configure", "sign", "enroll", "done"].indexOf(step)
                    ? "bg-green-500 text-white"
                    : "bg-gray-200 text-gray-500"
                }`}
              >
                {i + 1}
              </div>
              {i < 4 && <div className="w-8 h-px bg-gray-300" />}
            </div>
          )
        )}
      </div>

      {/* Error display */}
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4">
          {error}
        </div>
      )}

      {/* Step 1: Connect wallet */}
      {step === "connect" && (
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <h2 className="text-lg font-semibold mb-4">Connect Wallet</h2>
          <div className="flex flex-col gap-3">
            {connectors.map((connector) => (
              <button
                key={connector.uid}
                onClick={() => {
                  connect({ connector });
                  setStep("configure");
                }}
                className="w-full px-4 py-3 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium"
              >
                {connector.name}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Step 2: Configure policy */}
      {step === "configure" && (
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <h2 className="text-lg font-semibold mb-4">Configure Policy</h2>
          {isConnected && (
            <div className="flex items-center justify-between mb-4 p-3 bg-green-50 rounded-lg">
              <span className="text-sm text-green-700">
                Connected: {address?.slice(0, 6)}...{address?.slice(-4)}
              </span>
              <button
                onClick={() => {
                  disconnect();
                  setStep("connect");
                }}
                className="text-sm text-gray-500 hover:text-gray-700"
              >
                Disconnect
              </button>
            </div>
          )}
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Policy ID
              </label>
              <input
                type="text"
                value={policyId}
                onChange={(e) => setPolicyId(e.target.value)}
                placeholder="0x01ab...ef (64 hex chars)"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Scope
              </label>
              <input
                type="text"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                placeholder="e.g., defi-protocol-xyz"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Nonce
              </label>
              <input
                type="text"
                value={nonce}
                onChange={(e) => setNonce(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
            </div>
            <button
              onClick={() => setStep("sign")}
              disabled={!policyId}
              className="w-full px-4 py-3 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Continue
            </button>
          </div>
        </div>
      )}

      {/* Step 3: Sign message */}
      {step === "sign" && (
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <h2 className="text-lg font-semibold mb-4">Sign Message</h2>
          <div className="bg-gray-50 rounded-lg p-4 mb-4">
            <p className="text-sm text-gray-500 mb-1">Message to sign:</p>
            <code className="text-sm font-mono break-all">{message}</code>
          </div>
          <p className="text-sm text-gray-500 mb-4">
            Your wallet will prompt you to sign this message. This proves you
            control the wallet without transferring any funds.
          </p>
          <button
            onClick={handleSign}
            disabled={loading}
            className="w-full px-4 py-3 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium disabled:opacity-50"
          >
            {loading ? "Waiting for signature..." : "Sign Message"}
          </button>
        </div>
      )}

      {/* Step 4: Submit enrollment */}
      {step === "enroll" && (
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <h2 className="text-lg font-semibold mb-4">Submit Enrollment</h2>
          <div className="bg-green-50 rounded-lg p-4 mb-4">
            <p className="text-sm text-green-700">Signature obtained</p>
          </div>
          <p className="text-sm text-gray-500 mb-4">
            Click below to submit your enrollment to the Solvency Agent. Your
            wallet address will be monitored for solvency, but never exposed to
            verifiers.
          </p>
          <button
            onClick={handleEnroll}
            disabled={loading}
            className="w-full px-4 py-3 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium disabled:opacity-50"
          >
            {loading ? "Enrolling..." : "Enroll"}
          </button>
        </div>
      )}

      {/* Step 5: Success */}
      {step === "done" && memberId && (
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <h2 className="text-lg font-semibold mb-4 text-green-700">
            Enrollment Successful
          </h2>
          <div className="space-y-3">
            <div>
              <p className="text-sm text-gray-500">Member ID</p>
              <code className="text-sm font-mono break-all bg-gray-50 block p-2 rounded">
                {memberId}
              </code>
            </div>
            <div>
              <p className="text-sm text-gray-500">Policy ID</p>
              <code className="text-sm font-mono break-all bg-gray-50 block p-2 rounded">
                {policyId}
              </code>
            </div>
            <p className="text-sm text-gray-500">
              Save your Member ID. You&apos;ll need it to check your status and
              retrieve solvency proofs.
            </p>
            <button
              onClick={() => navigator.clipboard.writeText(memberId)}
              className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors text-sm"
            >
              Copy Member ID
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
