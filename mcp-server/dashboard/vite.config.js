import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: '../src/inalign_mcp/dashboard_dist',
    emptyOutDir: true,
  },
})
