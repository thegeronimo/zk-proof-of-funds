import { Routes, Route, Link, useLocation, Navigate } from "react-router-dom";
import ProveFlow from "./components/ProveFlow";
import SolventSetPanel from "./components/SolventSetPanel";
import IdentityPanel from "./components/IdentityPanel";
import ProofViewer from "./components/ProofViewer";
import OperatorPanel from "./components/OperatorPanel";
import MonitoredMode from "./components/MonitoredMode";
import { usePolicySelection } from "./hooks/usePolicySelection";
import { findPolicy } from "./config/policies";

/**
 * Navigation is ordered by the V2 flow: prove first, then the set it was
 * proven against, then identity, then the relying party's view. Monitored mode
 * sits last because it is the legacy path.
 */
const NAV = [
  { to: "/", label: "Prove" },
  { to: "/set", label: "Solvent set" },
  { to: "/identity", label: "Identity" },
  { to: "/verify", label: "Verify" },
  { to: "/operator", label: "Operator" },
  { to: "/monitored", label: "Monitored" },
];

function NavLink({ to, children }: { to: string; children: React.ReactNode }) {
  const { pathname } = useLocation();
  const active = pathname === to;
  return (
    <Link
      to={to}
      className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
        active
          ? "bg-primary-600 text-white"
          : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"
      }`}
    >
      {children}
    </Link>
  );
}

/** The active policy, shown in the header so it is never ambiguous. */
function PolicyBadge() {
  const { policyId, isValid } = usePolicySelection();
  const policy = findPolicy(policyId);
  if (!isValid) return null;
  return (
    <span
      className="hidden lg:inline-flex items-center gap-1.5 text-xs text-gray-500 border border-gray-200 rounded-full px-2.5 py-1"
      title={policyId}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
      {policy ? policy.description : `${policyId.slice(0, 10)}…`}
    </span>
  );
}

export default function App() {
  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white border-b border-gray-200 px-4 py-3 sticky top-0 z-10">
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 shrink-0">
            <Link to="/" className="text-lg font-bold text-primary-700">
              ZK Proof of Funds
            </Link>
            <PolicyBadge />
          </div>
          <div className="flex items-center gap-1 overflow-x-auto">
            {NAV.map((item) => (
              <NavLink key={item.to} to={item.to}>
                {item.label}
              </NavLink>
            ))}
          </div>
        </div>
      </nav>

      <main className="max-w-5xl mx-auto px-4 py-8">
        <Routes>
          <Route path="/" element={<ProveFlow />} />
          <Route path="/set" element={<SolventSetPanel />} />
          <Route path="/identity" element={<IdentityPanel />} />
          <Route path="/verify" element={<ProofViewer />} />
          <Route path="/operator" element={<OperatorPanel />} />
          <Route path="/monitored" element={<MonitoredMode />} />
          {/* Old paths from the V1-first app. */}
          <Route path="/solvent-set" element={<Navigate to="/set" replace />} />
          <Route path="/dashboard" element={<Navigate to="/monitored" replace />} />
          <Route path="/proof" element={<Navigate to="/verify" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
