import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const securityHeaders = {
  "Content-Security-Policy": "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws: wss:",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

export default defineConfig({
  plugins: [react()],
  server: {
    headers: securityHeaders,
    proxy: { "/api": { target: "http://127.0.0.1:8080", changeOrigin: true }, "/ws": { target: "ws://127.0.0.1:8080", ws: true } },
  },
  preview: {
    headers: securityHeaders,
    proxy: { "/api": { target: "http://127.0.0.1:8080", changeOrigin: true }, "/ws": { target: "ws://127.0.0.1:8080", ws: true } },
  },
});
