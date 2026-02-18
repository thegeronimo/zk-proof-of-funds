import { Routes, Route, Link, useLocation } from "react-router-dom";
import EnrollmentFlow from "./components/EnrollmentFlow";
import Dashboard from "./components/Dashboard";
import ProofViewer from "./components/ProofViewer";

function NavLink({ to, children }: { to: string; children: React.ReactNode }) {
  const { pathname } = useLocation();
  const active = pathname === to;
  return (
    <Link
      to={to}
      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
        active
          ? "bg-primary-600 text-white"
          : "text-gray-600 hover:text-gray-900 hover:bg-gray-100"
      }`}
    >
      {children}
    </Link>
  );
}

export default function App() {
  return (
    <div className="min-h-screen">
      {/* Navigation */}
      <nav className="bg-white border-b border-gray-200 px-4 py-3">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-lg font-bold text-primary-700">
              ZK Proof of Funds
            </span>
          </div>
          <div className="flex items-center gap-2">
            <NavLink to="/">Enroll</NavLink>
            <NavLink to="/dashboard">Dashboard</NavLink>
            <NavLink to="/proof">Proof Viewer</NavLink>
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main className="max-w-5xl mx-auto px-4 py-8">
        <Routes>
          <Route path="/" element={<EnrollmentFlow />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/proof" element={<ProofViewer />} />
        </Routes>
      </main>
    </div>
  );
}
