import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Vite runs inside the Express server during `npm run dev` (see
// server/server.js), so there's no separate dev server or proxy to configure.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    watch: {
      // server/ changes restart Node itself; data.json changes on every log.
      ignored: ['**/server/**', '**/data.json', '**/data.json.tmp'],
    },
    fs: {
      // Never let the dev server hand out secrets, stored accounts, or server code.
      deny: ['.env', '.env.*', '*.{crt,pem}', '**/.git/**', '**/data.json', '**/data.json.tmp', '**/server/**'],
    },
  },
})
