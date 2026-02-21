import { SolvencyClient } from "@zk-proof-of-funds/sdk";

// Use relative /api path by default so requests go through the Vite proxy
// (avoids CORS issues in dev). Override with VITE_AGENT_URL for production.
const AGENT_URL =
  import.meta.env.VITE_AGENT_URL || "/api";

/** Shared SolvencyClient instance for the web app. */
export const apiClient = new SolvencyClient({
  agentUrl: AGENT_URL,
  timeoutMs: 15_000,
});
