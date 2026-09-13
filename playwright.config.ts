import { defineConfig } from '@playwright/test';
export default defineConfig({ testDir: './test/e2e', use: { baseURL: 'http://127.0.0.1:3210' }, webServer: { command: 'npm run dev', port: 3210, reuseExistingServer: true } });
