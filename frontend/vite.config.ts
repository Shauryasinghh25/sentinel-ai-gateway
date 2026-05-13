import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/gateway': 'http://localhost:8000',
      '/security': 'http://localhost:8000',
      '/analytics': 'http://localhost:8000',
      '/policy': 'http://localhost:8000',
      '/metrics': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    }
  }
})
