import { defineConfig } from '@playwright/test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const e2eStoragePath = join(tmpdir(), `mcp-firewall-e2e-${process.pid}-${Date.now()}.json`);
export default defineConfig({ testDir: './test/e2e', use: { baseURL: 'http://127.0.0.1:3211' }, webServer: { command: `STORAGE_PATH=${e2eStoragePath} PORT=3211 npm run dev`, port: 3211, reuseExistingServer: false } });
