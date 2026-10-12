import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const apiProxy = {
  '/api': process.env.GUARDIAN_API_TARGET || 'http://localhost:8080',
  '/healthz': process.env.GUARDIAN_API_TARGET || 'http://localhost:8080',
  '/readyz': process.env.GUARDIAN_API_TARGET || 'http://localhost:8080',
}

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: apiProxy,
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
    proxy: apiProxy,
  },
})
