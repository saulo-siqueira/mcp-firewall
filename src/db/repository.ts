import type pg from 'pg';

export type Database = { db: unknown; pool: pg.Pool };

export async function ensureDatabase(database: Database) {
  await database.pool.query(`
    CREATE TABLE IF NOT EXISTS policies (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text UNIQUE NOT NULL, match jsonb NOT NULL, action text NOT NULL, enabled boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS mcp_servers (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text UNIQUE NOT NULL, transport text NOT NULL, command text, url text, status text NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_logs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), agent text NOT NULL, server text NOT NULL, tool text NOT NULL, decision text NOT NULL, policy text, arguments jsonb NOT NULL, duration integer NOT NULL, result jsonb, created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS admin_users (id text PRIMARY KEY, name text NOT NULL, email text UNIQUE NOT NULL, password_hash text NOT NULL, role text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS sessions (id text PRIMARY KEY, user_id text NOT NULL, created_at timestamptz NOT NULL, expires_at bigint NOT NULL);
    CREATE TABLE IF NOT EXISTS approvals (id text PRIMARY KEY, status text NOT NULL, agent text NOT NULL, server text NOT NULL, tool text NOT NULL, arguments jsonb NOT NULL, policy text, call jsonb NOT NULL, audit_id text, requested_at timestamptz NOT NULL, approved_by text, approved_at timestamptz, rejected_by text, rejected_at timestamptz);
  `);
}

export async function loadConfiguration(database: Database) {
  const [policyRows, serverRows, userRows, sessionRows, approvalRows] = await Promise.all([
    database.pool.query('SELECT name, match, action, enabled FROM policies ORDER BY created_at'),
    database.pool.query('SELECT name, transport, command, url, status FROM mcp_servers ORDER BY name'),
    database.pool.query('SELECT id, name, email, password_hash, role, created_at, updated_at FROM admin_users ORDER BY created_at'),
    database.pool.query('SELECT id, user_id, created_at, expires_at FROM sessions'),
    database.pool.query('SELECT * FROM approvals ORDER BY requested_at'),
  ]);
  return { policies: policyRows.rows, servers: serverRows.rows, users: userRows.rows, sessions: sessionRows.rows, approvals: approvalRows.rows };
}

export async function syncConfiguration(database: Database, firewall: any) {
  await database.pool.query('BEGIN');
  try {
    await database.pool.query('DELETE FROM policies');
    for (const policy of firewall.policies.values()) await database.pool.query('INSERT INTO policies (name, match, action, enabled) VALUES ($1, $2, $3, $4)', [policy.name, policy.match || {}, policy.action, policy.enabled]);
    await database.pool.query('DELETE FROM mcp_servers');
    for (const server of firewall.servers.values()) await database.pool.query('INSERT INTO mcp_servers (name, transport, command, url, status) VALUES ($1, $2, $3, $4, $5)', [server.name, server.transport, server.command || null, server.url || null, server.status || 'Disconnected']);
    await database.pool.query('DELETE FROM admin_users');
    for (const user of firewall.users.values()) await database.pool.query('INSERT INTO admin_users (id, name, email, password_hash, role, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)', [user.id, user.name, user.email, user.password_hash, user.role, user.created_at, user.updated_at]);
    await database.pool.query('DELETE FROM sessions');
    for (const session of firewall.sessions.values()) await database.pool.query('INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)', [session.id, session.userId, session.created_at, session.expires_at]);
    await database.pool.query('DELETE FROM approvals');
    for (const approval of firewall.approvals.values()) await database.pool.query('INSERT INTO approvals (id, status, agent, server, tool, arguments, policy, call, audit_id, requested_at, approved_by, approved_at, rejected_by, rejected_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)', [approval.id, approval.status, approval.agent, approval.server, approval.tool, approval.arguments, approval.policy, approval.call, approval.audit_id, approval.requested_at, approval.approved_by, approval.approved_at, approval.rejected_by, approval.rejected_at]);
    await database.pool.query('COMMIT');
  } catch (error) { await database.pool.query('ROLLBACK'); throw error; }
}

export async function appendAudit(database: Database, event: any) {
  await database.pool.query('INSERT INTO audit_logs (id, agent, server, tool, decision, policy, arguments, duration, result) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (id) DO UPDATE SET decision = EXCLUDED.decision, duration = EXCLUDED.duration, result = EXCLUDED.result', [event.id, event.agent, event.server, event.tool, event.decision, event.policy, event.arguments, event.duration, event.result]);
}
