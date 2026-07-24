import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  build: {
    lib: {
      // "index" is the zero-dependency core; "plume" is the wallet-side
      // nullifier module and pulls in @noble/curves + @noble/hashes.
      entry: {
        index: resolve(__dirname, "src/index.ts"),
        plume: resolve(__dirname, "src/plume.ts"),
      },
      formats: ["es"],
    },
    rollupOptions: {
      // Keep the audited crypto libraries external (declared dependencies).
      external: [/^@noble\//],
    },
    sourcemap: true,
    minify: false,
  },
});
