import { SolvencyClient } from "@zk-proof-of-funds/sdk";

const AGENT_URL =
  import.meta.env.VITE_AGENT_URL || "http://localhost:3000";

/** Shared SolvencyClient instance for the web app. */
export const apiClient = new SolvencyClient({
  agentUrl: AGENT_URL,
  timeoutMs: 15_000,
});
