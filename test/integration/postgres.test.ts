import { describe, expect, it } from 'vitest';
import { GenericContainer } from 'testcontainers';

describe.skipIf(!process.env.RUN_CONTAINERS)('PostgreSQL integration', () => {
  it('declares a runnable PostgreSQL container contract', async () => {
    const container = await new GenericContainer('postgres:16-alpine').withEnvironment({ POSTGRES_DB: 'mcp_firewall', POSTGRES_USER: 'mcp_firewall', POSTGRES_PASSWORD: 'mcp_firewall' }).withExposedPorts(5432).start();
    expect(container.getMappedPort(5432)).toBeGreaterThan(0);
    await container.stop();
  }, 120_000);
});
