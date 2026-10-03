import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies /api to the stdlib Python server (web/server.py on :8787).
// Build output goes to dist/, which web/server.py serves directly in prod.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
