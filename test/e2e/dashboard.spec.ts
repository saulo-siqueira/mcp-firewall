import { test, expect } from '@playwright/test';
test('dashboard route is reachable', async ({ page }) => { await page.goto('/api/dashboard?view=login'); await expect(page).toHaveTitle(/Login|MCP Firewall/); });
