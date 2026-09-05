/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    port: 5173,
    // Proxy the API in development so the browser sees a same-origin app.
    // This avoids CORS entirely and — more importantly — means the dev setup
    // matches production, where an ingress fronts both. A CORS-only dev setup
    // hides same-site cookie problems until deploy day.
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        ws: true, // scan progress is a WebSocket (docs/02-CONTRACTS.md §10)
      },

      // ⚠ THE RULE WRITTEN BELOW FOR ZITADEL, APPLIED TO OUR OWN PATH — WHICH
      // IT WAS NOT, AND SHARE LINKS 404'd IN `npm run dev`.
      //
      // `POST /v1/reports/{id}/shares` returns a URL of the form
      // `/shared/<token>`, and deploy/docker/nginx.conf routes /shared/ to the
      // gateway. This file did not, so in development the SPA router caught it
      // and rendered NotFound — a share link that works in production and
      // fails locally, which reads as a broken token rather than a missing
      // proxy rule. Exactly the failure the ZITADEL comment below describes.
      //
      // Unauthenticated by design: the token IS the credential, and the
      // gateway rate-limits it.
      '/shared': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },

      // ZITADEL's canonical paths, mirroring deploy/docker/nginx.conf.
      //
      // ⚠ THE TWO MUST AGREE. nginx serves the container build and this serves
      // `npm run dev`; a path present in one and missing in the other means
      // login works in production and 404s locally, or the reverse — and the
      // failure looks like a broken auth library rather than a missing proxy
      // rule. When you add a path there, add it here.
      //
      // ⚠ changeOrigin IS FALSE, DELIBERATELY. ZITADEL selects its virtual
      // instance from the Host header and bakes the issuer into every token.
      // Rewriting the Host to zitadel's own address makes it publish an issuer
      // of http://localhost:58080, which then mismatches the URL the browser
      // called and every token is rejected.
      ...Object.fromEntries(
        [
          '/.well-known',
          '/oauth/v2',
          '/oidc/v1',
          '/saml/v2',
          '/idps',
          '/assets/v1',
          '/admin/v1',
          '/auth/v1', // NOT '/auth' — the SPA owns /auth/callback
          '/management/v1',
          '/system/v1',
          '/v2',
          '/ui/console',
          '/ui/login',
          '/ui/v2/login',
          '/device',
        ].map((path) => [path, { target: 'http://localhost:58080', changeOrigin: false }]),
      ),
    },
  },
  build: {
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          // The dependency graph view is heavy and reached from one tab.
          // Splitting it keeps the initial bundle inside the 250 KB budget
          // in docs/07-FRONTEND-SPEC.md §8.
          vendor: ['react', 'react-dom', 'react-router'],
          query: ['@tanstack/react-query'],
        },
      },
    },
  },

  test: {
    // jsdom, not the default node environment: the components under test are
    // React, and the WebSocket client reaches for window.setTimeout.
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    // ⚠ EXCLUDE PLAYWRIGHT. Vitest would otherwise collect e2e/*.spec.ts and
    // fail on `@playwright/test` imports it cannot satisfy — which reads as a
    // broken unit suite rather than a misconfigured runner.
    exclude: ['node_modules/**', 'dist/**', 'e2e/**'],
  },
});
