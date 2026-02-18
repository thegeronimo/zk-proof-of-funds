import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "ZkProofOfFundsSDK",
      formats: ["es"],
      fileName: "index",
    },
    rollupOptions: {
      // No external dependencies — zero-dep library
    },
    sourcemap: true,
    minify: false,
  },
});
