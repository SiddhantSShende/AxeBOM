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
