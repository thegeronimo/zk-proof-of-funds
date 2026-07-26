import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@zk-proof-of-funds/sdk/plume": path.resolve(__dirname, "../sdk/src/plume.ts"),
      "@zk-proof-of-funds/sdk": path.resolve(__dirname, "../sdk/src/index.ts"),
      // The policy catalog is shared with the agent and the deploy script —
      // read the one in config/ rather than keeping a divergent copy here.
      "@zkpof/policies.json": path.resolve(__dirname, "../config/policies.json"),
    },
  },
  server: {
    port: 5173,
    // Allow serving config/policies.json and sdk/src, which live outside web/.
    fs: { allow: [path.resolve(__dirname, "..")] },
    proxy: {
      "/api": {
        target: "http://localhost:3000",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
});
