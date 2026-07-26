import { SolvencyClient } from "@zk-proof-of-funds/sdk";

// Use relative /api path by default so requests go through the Vite proxy
// (avoids CORS issues in dev). Override with VITE_AGENT_URL for production.
const AGENT_URL = import.meta.env.VITE_AGENT_URL || "/api";

/**
 * The agent's URL as a *separate process* would reach it.
 *
 * The browser talks to the agent through the dev proxy, but `zkpof-client`
 * runs outside it, so the generated CLI commands need a real origin. When
 * VITE_AGENT_URL is unset this mirrors the proxy target in vite.config.ts.
 */
export const AGENT_PUBLIC_URL =
  import.meta.env.VITE_AGENT_URL || "http://localhost:3000";

/** Shared SolvencyClient instance for the web app. */
export const apiClient = new SolvencyClient({
  agentUrl: AGENT_URL,
  timeoutMs: 15_000,
});
