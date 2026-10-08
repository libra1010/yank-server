import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// Dev only: the console talks to the Go server on its own origin in production
// (syncd embeds dist/ as webdist and serves both the API and the page).
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8899',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // The embedded console is served from a Go binary; no CDN, no external fonts.
    assetsInlineLimit: 4096,
  },
});
