import { describe, expect, it } from 'vitest';
import { GenericContainer } from 'testcontainers';
import pg from 'pg';
import { ensureDatabase, loadConfiguration, syncConfiguration } from '../../src/db/repository.ts';

describe.skipIf(!process.env.RUN_CONTAINERS)('PostgreSQL integration', () => {
  it('persists and reloads the MVP configuration in PostgreSQL', async () => {
    const container = await new GenericContainer('postgres:16-alpine').withEnvironment({ POSTGRES_DB: 'mcp_firewall', POSTGRES_USER: 'mcp_firewall', POSTGRES_PASSWORD: 'mcp_firewall' }).withExposedPorts(5432).start();
    const pool = new pg.Pool({ host: container.getHost(), port: container.getMappedPort(5432), database: 'mcp_firewall', user: 'mcp_firewall', password: 'mcp_firewall' });
    try {
      const database = { db: {}, pool };
      await ensureDatabase(database);
      const firewall = { policies: new Map([['p', { name: 'p', match: { tool: 'safe.read' }, action: 'allow', enabled: true }]]), servers: new Map([['s', { name: 's', transport: 'http', url: 'http://mock', status: 'Disconnected' }]]), users: new Map(), sessions: new Map(), approvals: new Map() };
      await syncConfiguration(database, firewall);
      const loaded = await loadConfiguration(database);
      expect(loaded.policies).toHaveLength(1);
      expect(loaded.policies[0].name).toBe('p');
      expect(loaded.servers[0].transport).toBe('http');
    } finally { await pool.end(); await container.stop(); }
  }, 120_000);
});
