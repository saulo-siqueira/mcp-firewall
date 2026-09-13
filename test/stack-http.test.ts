import { expect, test } from 'vitest';
import { app, firewall } from '../src/server.ts';

async function withCleanFirewall(run: () => Promise<void>) {
  const original = { storagePath: firewall.storagePath, configPath: firewall.configPath, policies: new Map(firewall.policies), servers: new Map(firewall.servers), audit: new Map(firewall.audit), approvals: new Map(firewall.approvals) };
  try { firewall.storagePath = null; firewall.configPath = null; firewall.policies.clear(); firewall.servers.clear(); firewall.audit.clear(); firewall.approvals.clear(); await run(); }
  finally { firewall.storagePath = original.storagePath; firewall.configPath = original.configPath; firewall.policies = original.policies; firewall.servers = original.servers; firewall.audit = original.audit; firewall.approvals = original.approvals; }
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
