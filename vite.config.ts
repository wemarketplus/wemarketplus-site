import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// The NestJS backend's listen port is configurable (wemarketplus-backend/.env
// PORT, default 3000 — set to 4200 on some machines). Point the dev proxy at it
// via VITE_BACKEND_ORIGIN so a non-default backend port doesn't 404 every call.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendOrigin = env.VITE_BACKEND_ORIGIN || 'http://localhost:3000';

  return {
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    server: {
      port: 3001,
      proxy: {
        // The backend mounts every route under its own `/api` global prefix
        // (app.setGlobalPrefix('api')). Our client also calls `/api/...`
        // (VITE_API_BASE_URL defaults to `/api`). Forward the path UNCHANGED —
        // `/api/auth/login` -> `<backendOrigin>/api/auth/login`. Do NOT strip
        // `/api`, or every request 404s against the backend.
        '/api': {
          target: backendOrigin,
          changeOrigin: true,
        },
      },
    },
  };
});
