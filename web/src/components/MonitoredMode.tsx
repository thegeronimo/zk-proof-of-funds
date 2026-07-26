/**
 * Monitored mode (V1) — enrollment plus the member dashboard.
 *
 * Kept because trusted-mode policies still run on it, but framed honestly
 * against the solvent-set flow: here the member registers with the agent and
 * the agent watches an address on their behalf, which is a weaker privacy
 * position than proving membership of a public set. The two produce the same
 * identity to a relying protocol.
 */

import { useState } from "react";
import EnrollmentFlow from "./EnrollmentFlow";
import Dashboard from "./Dashboard";
import { Callout, PageHeader } from "./ui";

type Tab = "enroll" | "dashboard";

export default function MonitoredMode() {
  const [tab, setTab] = useState<Tab>("enroll");

  return (
    <div>
      <div className="max-w-3xl mx-auto">
        <PageHeader title="Monitored mode">
          The original flow: enroll once, and the agent tracks your balance and publishes a
          membership root each epoch.
        </PageHeader>

        <div className="mb-6">
          <Callout tone="info" title="Consider the solvent-set flow instead">
            Monitored mode requires the agent to know which address to watch. The “Prove” tab needs
            no enrollment at all and never reveals your address — the anonymity set is every
            solvent address on the chain. Both produce the same identity to a relying protocol, so
            they are interchangeable per policy.
          </Callout>
        </div>

        <div className="flex gap-1 mb-6 bg-gray-100 p-1 rounded-lg w-fit">
          {(
            [
              ["enroll", "Enroll"],
              ["dashboard", "Dashboard"],
            ] as [Tab, string][]
          ).map(([value, label]) => (
            <button
              key={value}
              onClick={() => setTab(value)}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                tab === value
                  ? "bg-white shadow-sm text-gray-900"
                  : "text-gray-600 hover:text-gray-900"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {tab === "enroll" ? <EnrollmentFlow /> : <Dashboard />}
    </div>
  );
}
