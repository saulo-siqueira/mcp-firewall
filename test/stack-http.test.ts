import { expect, test } from 'vitest';
import { app, firewall } from '../src/server.ts';

async function withCleanFirewall(run: () => Promise<void>) {
  const original = { storagePath: firewall.storagePath, configPath: firewall.configPath, policies: new Map(firewall.policies), servers: new Map(firewall.servers), users: new Map(firewall.users), sessions: new Map(firewall.sessions), audit: new Map(firewall.audit), approvals: new Map(firewall.approvals) };
  try { firewall.storagePath = null; firewall.configPath = null; firewall.policies.clear(); firewall.servers.clear(); firewall.users.clear(); firewall.sessions.clear(); firewall.audit.clear(); firewall.approvals.clear(); await run(); }
  finally { firewall.storagePath = original.storagePath; firewall.configPath = original.configPath; firewall.policies = original.policies; firewall.servers = original.servers; firewall.users = original.users; firewall.sessions = original.sessions; firewall.audit = original.audit; firewall.approvals = original.approvals; }
}

test('Fastify exposes the production MCP compatibility boundary for ALLOW', async () => withCleanFirewall(async () => {
  firewall.addPolicy({ name: 'allow-test', match: { tool: 'test.echo' }, action: 'allow', enabled: true });
  firewall.addServer({ name: 'mock', transport: 'stdio', command: process.execPath, args: ['-e', "process.stdin.on('data',()=>process.stdout.write(JSON.stringify({ok:true})))"] });
  const response = await app.inject({ method: 'POST', url: '/mcp/tools/call', payload: { agent: 'test', server: 'mock', tool: 'test.echo', arguments: {} } });
  expect(response.statusCode).toBe(200); expect(response.json().decision).toBe('ALLOW');
}));

test('Fastify compatibility boundary enforces DENY and REQUIRE_APPROVAL with redacted audit', async () => withCleanFirewall(async () => {
  firewall.addPolicy({ name: 'deny-test', match: { tool: 'test.deny' }, action: 'deny', enabled: true });
  firewall.addPolicy({ name: 'approval-test', match: { tool: 'test.approve' }, action: 'require_approval', enabled: true });
  const denied = await app.inject({ method: 'POST', url: '/mcp/tools/call', payload: { tool: 'test.deny', arguments: { token: 'secret-value' } } });
  expect(denied.statusCode).toBe(403); expect(denied.json().decision).toBe('DENY');
  const approval = await app.inject({ method: 'POST', url: '/mcp/tools/call', payload: { tool: 'test.approve', arguments: { password: 'secret-value' } } });
  expect(approval.statusCode).toBe(202); expect(approval.json().decision).toBe('REQUIRE_APPROVAL'); expect(JSON.stringify([...firewall.audit.values()])).not.toContain('secret-value');
}));

test('Fastify exposes MCP initialize and rejects an unknown SDK session', async () => {
  const initialize = await app.inject({ method: 'POST', url: '/mcp', payload: { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} } });
  expect(initialize.statusCode).toBe(200); expect(initialize.headers['mcp-protocol-version']).toBe('2025-06-18');
  const missing = await app.inject({ method: 'GET', url: '/mcp/sdk', headers: { 'mcp-session-id': 'missing' } });
  expect(missing.statusCode).toBe(400); expect(missing.json().error).toBe('MCP_SESSION_REQUIRED');
});

test('Fastify maps target transport failures to 502', async () => withCleanFirewall(async () => {
  firewall.addPolicy({ name: 'allow-failing-target', match: { tool: 'test.fail' }, action: 'allow', enabled: true });
  firewall.addServer({ name: 'missing-target', transport: 'http', url: 'http://127.0.0.1:1/unreachable' });
  const response = await app.inject({ method: 'POST', url: '/mcp/tools/call', payload: { server: 'missing-target', tool: 'test.fail', arguments: {} } });
  expect(response.statusCode).toBe(502); expect(response.json().error.code).toBe('TARGET_ERROR');
}));

test('MCP JSON-RPC boundary preserves request ids and maps target errors', async () => withCleanFirewall(async () => {
  firewall.addPolicy({ name: 'allow-http', match: { tool: 'test.echo' }, action: 'allow', enabled: true });
  firewall.addServer({ name: 'missing-target', transport: 'http', url: 'http://127.0.0.1:1/unreachable' });
  const response = await app.inject({ method: 'POST', url: '/mcp', payload: { jsonrpc: '2.0', id: 17, method: 'tools/call', params: { server: 'missing-target', name: 'test.echo', arguments: {} } } });
  expect(response.statusCode).toBe(502); expect(response.json().jsonrpc).toBe('2.0'); expect(response.json().id).toBe(17); expect(response.json().error.data.error.code).toBe('TARGET_ERROR');
}));

test('approval API distinguishes missing from non-pending approvals', async () => withCleanFirewall(async () => {
  firewall.setupAdmin({ name: 'Admin', email: 'admin@example.com', password: 'pw', confirmPassword: 'pw' });
  const session = firewall.login('admin@example.com', 'pw').session.id;
  const missing = firewall.api('POST', '/api/approvals/missing/reject', {}, session);
  expect(missing.status).toBe(404);
  firewall.addPolicy({ name: 'approval', match: { tool: 'test.approve' }, action: 'require_approval', enabled: true });
  const pending = await firewall.handleCall({ tool: 'test.approve', arguments: {} });
  firewall.approve(pending.approval.id, 'Admin');
  const nonPending = firewall.api('POST', `/api/approvals/${pending.approval.id}/reject`, {}, session);
  expect(nonPending.status).toBe(409);
}));

test('dashboard API returns metrics JSON and setup authenticates the new admin', async () => withCleanFirewall(async () => {
  const setup = firewall.api('POST', '/api/auth/setup', { name: 'Admin', email: 'new@example.com', password: 'pw', confirmPassword: 'pw' });
  expect(setup.status).toBe(201); expect(setup.body.session.id).toBeTruthy();
  const dashboard = firewall.api('GET', '/api/dashboard', {}, setup.body.session.id);
  expect(dashboard.status).toBe(200); expect(dashboard.body.total_tool_calls).toBe(0); expect(dashboard.body.recent_calls).toEqual([]);
}));
