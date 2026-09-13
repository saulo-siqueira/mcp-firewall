import type pg from 'pg';

export type Database = { db: unknown; pool: pg.Pool };

export async function ensureDatabase(database: Database) {
  await database.pool.query(`
    CREATE TABLE IF NOT EXISTS policies (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text UNIQUE NOT NULL, match jsonb NOT NULL, action text NOT NULL, enabled boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS mcp_servers (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text UNIQUE NOT NULL, transport text NOT NULL, command text, url text, status text NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_logs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), agent text NOT NULL, server text NOT NULL, tool text NOT NULL, decision text NOT NULL, policy text, arguments jsonb NOT NULL, duration integer NOT NULL, result jsonb, created_at timestamptz NOT NULL DEFAULT now());
  `);
}

export async function loadConfiguration(database: Database) {
  const [policyRows, serverRows] = await Promise.all([
    database.pool.query('SELECT name, match, action, enabled FROM policies ORDER BY created_at'),
    database.pool.query('SELECT name, transport, command, url, status FROM mcp_servers ORDER BY name'),
  ]);
  return { policies: policyRows.rows, servers: serverRows.rows };
}

export async function syncConfiguration(database: Database, firewall: any) {
  await database.pool.query('BEGIN');
  try {
    await database.pool.query('DELETE FROM policies');
    for (const policy of firewall.policies.values()) await database.pool.query('INSERT INTO policies (name, match, action, enabled) VALUES ($1, $2, $3, $4)', [policy.name, policy.match || {}, policy.action, policy.enabled]);
    await database.pool.query('DELETE FROM mcp_servers');
    for (const server of firewall.servers.values()) await database.pool.query('INSERT INTO mcp_servers (name, transport, command, url, status) VALUES ($1, $2, $3, $4, $5)', [server.name, server.transport, server.command || null, server.url || null, server.status || 'Disconnected']);
    await database.pool.query('COMMIT');
  } catch (error) { await database.pool.query('ROLLBACK'); throw error; }
}

export async function appendAudit(database: Database, event: any) {
  await database.pool.query('INSERT INTO audit_logs (id, agent, server, tool, decision, policy, arguments, duration, result) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (id) DO UPDATE SET decision = EXCLUDED.decision, duration = EXCLUDED.duration, result = EXCLUDED.result', [event.id, event.agent, event.server, event.tool, event.decision, event.policy, event.arguments, event.duration, event.result]);
}
