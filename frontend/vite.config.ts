import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitest/config";

// The app is served under /console so its client-side routes can never shadow
// the backend's /investigations API routes. In development the Vite server
// forwards ONLY /api to the local FastAPI backend (same origin for the
// browser, so the HttpOnly session cookie works without CORS).
const backend = process.env.PRIVATE_AI_BACKEND_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  base: "/console/",
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  server: {
    port: 5173,
    proxy: { "/api": { target: backend } },
  },
  build: { sourcemap: false, target: "es2022" },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
