import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The build is embedded into the Go binary (internal/web/ui). Everything is
// bundled locally: the page loads no third-party scripts, fonts or styles.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: '../internal/web/ui/dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
    chunkSizeWarningLimit: 400,
  },
  server: {
    proxy: {
      '/api': { target: process.env.NET_WATCHER_API ?? 'http://localhost:8920', ws: true },
    },
  },
});
