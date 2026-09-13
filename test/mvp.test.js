import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import http from 'node:http';
import { PassThrough } from 'node:stream';
import { Firewall, createApiServer, createMcpCall, handleMcpMessage, parseConfigYaml, startStdioGateway } from '../src/index.js';

const context = (overrides = {}) => ({
  agent: 'claude-code', server: 'filesystem', tool: 'filesystem.read',
  arguments: { path: '/tmp/readme' }, ...overrides,
});

test('gateway_identifies_tool_call_context', async () => {
  const firewall = new Firewall();
  const call = createMcpCall(context());
  assert.deepEqual(call, context());
  const result = await new Firewall({ servers: [{ name: 'filesystem', handler: async (received) => received }], policies: [{ match: { tool: 'filesystem.read' }, action: 'allow', enabled: true }] }).handleCall(call);
  assert.equal(result.result.tool, 'filesystem.read');
});

test('gateway_forwards_call_with_explicit_allow', async () => {
  let invoked = 0;
  const firewall = new Firewall({ servers: [{ name: 'filesystem', transport: 'stdio', handler: async () => { invoked++; return { ok: true }; } }], policies: [{ name: 'read', match: { tool: 'filesystem.read' }, action: 'allow', enabled: true }] });
  const result = await firewall.handleCall(context());
  assert.equal(result.decision, 'ALLOW'); assert.deepEqual(result.result, { ok: true }); assert.equal(invoked, 1);
});

test('gateway_denies_call_without_target_invocation', async () => {
  let invoked = 0;
  const firewall = new Firewall({ servers: [{ name: 'filesystem', handler: async () => { invoked++; } }] });
  const result = await firewall.handleCall(context());
  assert.equal(result.decision, 'DENY'); assert.equal(invoked, 0); assert.equal(result.error.code, 'POLICY_DENIED');
});

test('gateway_defaults_to_deny_without_matching_policy', async () => {
  let invoked = false;
  const firewall = new Firewall({ servers: [{ name: 'filesystem', handler: async () => { invoked = true; } }], policies: [{ name: 'other', match: { tool: 'other' }, action: 'allow', enabled: true }] });
  assert.equal((await firewall.handleCall(context())).decision, 'DENY');
  assert.equal(invoked, false);
});

test('policy_precedence_restrictiveness_table', async () => {
  const firewall = new Firewall({ policies: [
    { name: 'allow', match: { tool: 'filesystem.*' }, action: 'allow', enabled: true },
    { name: 'approval', match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true },
    { name: 'deny', match: { tool: 'filesystem.read' }, action: 'deny', enabled: true },
  ] });
  assert.equal((await firewall.evaluate(context())).decision, 'DENY');
  assert.equal((await new Firewall({ policies: [{ match: { tool: 'filesystem.*' }, action: 'allow', enabled: true }, { match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true }] }).evaluate(context())).decision, 'REQUIRE_APPROVAL');
  assert.equal((await new Firewall({ policies: [{ match: { tool: 'filesystem.*' }, action: 'allow', enabled: true }] }).evaluate(context())).decision, 'ALLOW');
});

test('gateway_uses_stdio_transport', async () => {
  const firewall = new Firewall({ servers: [{ name: 'filesystem', transport: 'stdio', command: process.execPath, args: ['-e', "process.stdin.on('data',()=>process.stdout.write(JSON.stringify({transport:'stdio'})))"] }], policies: [{ match: { tool: 'filesystem.read' }, action: 'allow', enabled: true }] });
  assert.equal((await firewall.handleCall(context())).result.transport, 'stdio');
});

test('gateway_uses_streamable_http_transport', async () => {
  const target = http.createServer((request, response) => { request.resume(); request.on('end', () => { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ transport: 'http' })); }); });
  await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve)); const address = target.address();
  const firewall = new Firewall({ servers: [{ name: 'filesystem', transport: 'http', url: `http://127.0.0.1:${address.port}` }], policies: [{ match: { tool: 'filesystem.read' }, action: 'allow', enabled: true }] });
  assert.equal((await firewall.handleCall(context())).result.transport, 'http'); await new Promise((resolve) => target.close(resolve));
});
test('config_yaml_loads_policy_and_server_contract', async () => { const config = parseConfigYaml('version: 1\npolicies:\n  - name: read\n    match:\n      tool: filesystem.*\n    action: allow\n    enabled: true\nmcp_servers:\n  - name: files\n    transport: stdio\n    command: node\n'); assert.equal(config.policies[0].match.tool, 'filesystem.*'); assert.equal(config.policies[0].action, 'allow'); assert.equal(config.mcp_servers[0].transport, 'stdio'); });
test('stdio_target_is_invoked_and_missing_target_fails', async () => { const firewall = new Firewall({ servers: [{ name: 'stdio', transport: 'stdio', command: process.execPath, args: ['-e', "process.stdin.on('data',()=>process.stdout.write(JSON.stringify({ok:true,transport:'stdio'})))"] }], policies: [{ match: { tool: 'x' }, action: 'allow', enabled: true }] }); assert.equal((await firewall.handleCall({ agent: 'a', server: 'stdio', tool: 'x', arguments: {} })).result.transport, 'stdio'); const missing = await new Firewall({ policies: [{ match: { tool: 'x' }, action: 'allow', enabled: true }] }).handleCall({ agent: 'a', server: 'missing', tool: 'x', arguments: {} }); assert.equal(missing.error.code, 'TARGET_ERROR'); });
test('stdio_gateway_accepts_json_rpc_tool_calls', async () => { const input = new PassThrough(); const output = new PassThrough(); let text = ''; output.on('data', (chunk) => { text += chunk; }); const firewall = new Firewall({ servers: [{ name: 's', handler: async () => ({ ok: true }) }], policies: [{ match: { tool: 'x' }, action: 'allow', enabled: true }] }); startStdioGateway(firewall, input, output); input.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { agent: 'a', server: 's', name: 'x', arguments: {} } }) + '\n'); await new Promise((resolve) => setTimeout(resolve, 10)); const response = JSON.parse(text); assert.equal(response.id, 1); assert.equal(response.result.decision, 'ALLOW'); assert.equal('error' in response, false); });
test('mcp_json_rpc_negotiates_initialize_and_tool_listing', async () => { const firewall = new Firewall(); const initialized = await handleMcpMessage(firewall, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }); assert.equal(initialized.protocolVersion, '2025-06-18'); assert.deepEqual((await handleMcpMessage(firewall, { jsonrpc: '2.0', id: 2, method: 'tools/list' })).tools, []); });
test('redaction_covers_secret_assignments_and_policy_updates_validate_actions', async () => { const firewall = new Firewall({ servers: [{ name: 's', handler: async (call) => call.arguments }], policies: [{ name: 'p', match: { tool: 'x' }, action: 'allow', enabled: true }] }); const result = await firewall.handleCall({ agent: 'a', server: 's', tool: 'x', arguments: { text: 'DATABASE_PASSWORD=raw-secret' } }); assert.equal(result.result.text, 'DATABASE_PASSWORD=[REDACTED]'); assert.throws(() => firewall.updatePolicy('p', { action: 'bogus' }), /invalid policy action/); });
test('persistent_firewall_restores_policies_users_sessions_and_audit', async () => { const { mkdtemp } = await import('node:fs/promises'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path'); const { readFile } = await import('node:fs/promises'); const dir = await mkdtemp(join(tmpdir(), 'mcp-fw-store-')); const storagePath = join(dir, 'state.json'); const first = new Firewall({ storagePath, servers: [{ name: 's', handler: async () => ({ ok: true }) }], policies: [{ name: 'p', match: { tool: 'x' }, action: 'allow', enabled: true }] }); first.setupAdmin({ name: 'Admin', email: 'a@example.com', password: 'pw', confirmPassword: 'pw' }); const session = first.login('a@example.com', 'pw').session; await first.handleCall({ agent: 'a', server: 's', tool: 'x', arguments: {} }); const restored = new Firewall({ storagePath }); assert.ok(restored.getPolicy('p')); assert.equal(restored.users.size, 1); assert.equal(restored.sessions.has(session.id), true); assert.equal(restored.audit.size, 1); assert.match(await readFile(storagePath, 'utf8'), /created_at/); });

test('secret_scanner_redacts_initial_categories_before_forwarding', async () => {
  let received;
  const firewall = new Firewall({ servers: [{ name: 'filesystem', handler: async (call) => { received = call.arguments; return true; } }], policies: [{ match: { tool: 'filesystem.read' }, action: 'allow', enabled: true }] });
  await firewall.handleCall(context({ arguments: { apiKey: 'a', token: 'b', password: 'c', privateKey: 'd', environmentSecret: 'e' } }));
  assert.deepEqual(received, { apiKey: '[REDACTED]', token: '[REDACTED]', password: '[REDACTED]', privateKey: '[REDACTED]', environmentSecret: '[REDACTED]' });
});

test('audit_event_contains_required_fields_for_each_decision', async () => {
  for (const action of ['allow', 'deny', 'require_approval']) { const firewall = new Firewall({ servers: [{ name: 'filesystem', handler: async () => ({ ok: true }) }], policies: [{ match: { tool: 'filesystem.read' }, action, enabled: true }] }); const event = (await firewall.handleCall(context())).audit; for (const key of ['id', 'agent', 'server', 'tool', 'arguments', 'decision', 'policy', 'duration', 'result', 'created_at']) assert.ok(key in event); }
});

test('audit_event_never_persists_raw_secret', async () => {
  const firewall = new Firewall({ policies: [{ match: { tool: 'filesystem.read' }, action: 'deny', enabled: true }] });
  const event = (await firewall.handleCall(context({ arguments: { password: 'raw-secret' } }))).audit;
  assert.equal(JSON.stringify(event).includes('raw-secret'), false); assert.equal(event.arguments.password, '[REDACTED]');
});

test('approval_request_starts_pending_with_redacted_context', async () => {
  const firewall = new Firewall({ policies: [{ name: 'approve', match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true }] });
  const result = await firewall.handleCall(context({ arguments: { password: 'secret' } }));
  assert.equal(result.approval.status, 'PENDING'); assert.equal(result.approval.arguments.password, '[REDACTED]'); for (const key of ['agent', 'server', 'tool', 'requested_at', 'policy', 'call']) assert.ok(key in result.approval);
});

test('approval_approve_executes_once_and_records_approver', async () => {
  let calls = 0; const firewall = new Firewall({ servers: [{ name: 'filesystem', handler: async () => { calls++; return 'done'; } }], policies: [{ match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true }] });
  const pending = await firewall.handleCall(context()); const result = await firewall.approve(pending.approval.id, 'admin');
  assert.equal(result.approval.status, 'APPROVED'); assert.equal(calls, 1); assert.equal(result.approval.approved_by, 'admin'); assert.ok(result.approval.approved_at);
});

test('approval_reject_never_invokes_target', async () => {
  let calls = 0; const firewall = new Firewall({ servers: [{ name: 'filesystem', handler: async () => { calls++; } }], policies: [{ match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true }] });
  const pending = await firewall.handleCall(context()); const result = await firewall.reject(pending.approval.id, 'admin');
  assert.equal(result.approval.status, 'REJECTED'); assert.equal(calls, 0);
});

test('approval_unavailable_blocks_and_audits', async () => {
  const firewall = new Firewall({ policies: [{ match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true }], approvalAvailable: false });
  const result = await firewall.handleCall(context()); assert.equal(result.decision, 'DENY'); assert.equal(result.error.code, 'APPROVAL_UNAVAILABLE'); assert.ok(result.audit);
});

test('auth_setup_creates_first_admin', async () => { const firewall = new Firewall(); const user = firewall.setupAdmin({ name: 'Admin', email: 'a@example.com', password: 'pw', confirmPassword: 'pw' }); assert.equal(user.role, 'ADMIN'); assert.notEqual(user.password_hash, 'pw'); });
test('auth_login_creates_session_and_opens_dashboard', async () => { const firewall = new Firewall(); firewall.setupAdmin({ name: 'Admin', email: 'a@example.com', password: 'pw', confirmPassword: 'pw' }); const login = firewall.login('a@example.com', 'pw'); assert.ok(login.session); assert.equal(firewall.authorize(login.session.id), true); });
test('auth_invalid_credentials_create_no_session', async () => { const firewall = new Firewall(); firewall.setupAdmin({ name: 'Admin', email: 'a@example.com', password: 'pw', confirmPassword: 'pw' }); assert.throws(() => firewall.login('a@example.com', 'bad')); assert.equal(firewall.sessions.size, 0); });
test('auth_expired_or_logged_out_session_is_rejected', async () => { const firewall = new Firewall(); firewall.setupAdmin({ name: 'Admin', email: 'a@example.com', password: 'pw', confirmPassword: 'pw' }); const session = firewall.login('a@example.com', 'pw').session; firewall.logout(session.id); assert.equal(firewall.authorize(session.id), false); const expired = firewall.login('a@example.com', 'pw').session; expired.expires_at = Date.now() - 1; assert.equal(firewall.authorize(expired.id), false); });
test('policies_admin_crud_toggle_and_yaml_representation', async () => { const firewall = new Firewall(); firewall.addPolicy({ name: 'read: prod', match: { tool: 'x:*' }, action: 'allow', enabled: true }); firewall.updatePolicy('read: prod', { enabled: false }); assert.equal(firewall.getPolicy('read: prod').enabled, false); assert.match(firewall.policyYaml('read: prod'), /name: "read: prod"/); assert.match(firewall.policyYaml('read: prod'), /tool: "x:\*"/); firewall.deletePolicy('read: prod'); assert.equal(firewall.getPolicy('read: prod'), undefined); });
test('mcp_servers_accept_only_mvp_transports', async () => { const firewall = new Firewall(); firewall.addServer({ name: 'db', transport: 'http', url: 'x', status: 'Disconnected' }); firewall.addServer({ name: 'stdio', transport: 'stdio', command: 'node', status: 'Connected' }); assert.equal(firewall.servers.get('db').transport, 'http'); assert.equal(firewall.servers.get('stdio').command, 'node'); assert.throws(() => firewall.addServer({ name: 'x', transport: 'websocket' })); assert.throws(() => firewall.addServer({ name: 'bad', transport: 'http', status: 'Unknown' })); });
test('mcp_servers_admin_crud_and_dashboard_delete_control', async () => { const firewall = new Firewall(); firewall.addServer({ name: 'db', transport: 'http', url: 'http://db' }); assert.equal(firewall.updateServer('db', { status: 'Connected' }).status, 'Connected'); assert.match(firewall.serversHtml(), /data-delete-server/); assert.equal(firewall.deleteServer('db'), true); });
test('dashboard_renders_required_metrics_and_sections', async () => { const firewall = new Firewall({ servers: [{ name: 'filesystem', handler: async () => ({ ok: true }) }], policies: [{ name: 'active', match: { tool: 'filesystem.read' }, action: 'allow', enabled: true }] }); await firewall.handleCall(context()); const html = firewall.dashboardHtml(); for (const label of ['Total Tool Calls', 'Allowed', 'Blocked', 'Requires Approval', 'Recent Calls', 'Calls over time', 'Active Policies', 'Most used tools', 'Secrets Intercepted', 'Dashboard', 'Tool Calls', 'Policies', 'MCP Servers', 'Approvals', 'Audit Logs', 'Settings']) assert.match(html, new RegExp(label)); assert.match(html, /shell-sidebar/); assert.match(html, /shell-header/); });
test('audit_detail_renders_redacted_call_and_approval_data', async () => { const firewall = new Firewall({ servers: [{ name: 'filesystem', handler: async () => ({ ok: true }) }], policies: [{ match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true }] }); const result = await firewall.handleCall(context({ arguments: { password: 'secret' } })); await firewall.approve(result.approval.id, 'admin'); const html = firewall.auditDetailHtml(result.audit.id); for (const value of ['[REDACTED]', 'filesystem.read', 'APPROVED', 'admin', 'approved_at', 'duration', 'policy']) assert.match(html, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))); });
test('approvals_screen_lists_pending_requests_and_actions', async () => { const firewall = new Firewall({ policies: [{ name: 'sensitive', match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true }] }); await firewall.handleCall(context({ arguments: { password: 'secret' } })); const html = firewall.approvalsHtml(); for (const value of ['PENDING', 'claude-code', 'filesystem', 'filesystem.read', '[REDACTED]', 'sensitive', 'Approve', 'Reject']) assert.match(html, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))); });
test('mcp_servers_screen_renders_allowed_statuses', async () => { const firewall = new Firewall(); firewall.addServer({ name: 'db', transport: 'http', url: 'x' }); firewall.addServer({ name: 'ok', transport: 'http', url: 'x', status: 'Connected' }); firewall.addServer({ name: 'bad', transport: 'http', url: 'x', status: 'Error' }); const html = firewall.serversHtml(); assert.match(html, /Disconnected/); assert.match(html, /Connected/); assert.match(html, /Error/); });
test('admin_screens_render_command_center_sections', async () => { const firewall = new Firewall(); assert.match(firewall.loginHtml(), /Create Admin Account/); assert.match(firewall.toolCallsHtml(), /Tool Calls/); assert.match(firewall.policiesHtml(), /Policies/); assert.match(firewall.settingsHtml(), /Settings/); });
test('admin_screens_expose_loading_and_error_states', async () => { const firewall = new Firewall(); for (const html of [firewall.dashboardHtml(), firewall.toolCallsHtml(), firewall.policiesHtml(), firewall.serversHtml(), firewall.approvalsHtml()]) { assert.match(html, /Loading/); assert.match(html, /Error/); } });
test('admin_navigation_renders_each_route_view', async () => { const firewall = new Firewall(); for (const view of ['dashboard', 'tool-calls', 'policies', 'mcp-servers', 'approvals', 'audit-logs', 'settings']) assert.match(firewall.renderView(view), new RegExp(view.replace('-', ' '), 'i')); });
test('admin_screens_render_live_collections', async () => { const firewall = new Firewall({ policies: [{ name: 'read', match: { tool: 'x' }, action: 'allow', enabled: true }], servers: [{ name: 'db', transport: 'http', status: 'Connected' }] }); await firewall.handleCall(context()); assert.match(firewall.toolCallsHtml(), /filesystem\.read/); assert.match(firewall.policiesHtml(), /read/); assert.match(firewall.serversHtml(), /Connected/); assert.match(firewall.approvalsHtml(), /No pending approvals/); firewall.setupAdmin({ name: 'Admin', email: 'a@example.com', password: 'pw', confirmPassword: 'pw' }); const session = firewall.login('a@example.com', 'pw').session.id; const policies = firewall.api('GET', '/api/policies', {}, session); assert.equal(policies.status, 200); assert.equal(policies.body[0].name, 'read'); });
test('admin_api_authenticates_and_mutates_resources', async () => { const firewall = new Firewall({ policies: [{ name: 'approve', match: { tool: 'x' }, action: 'require_approval', enabled: true }] }); const setup = firewall.api('POST', '/api/auth/setup', { name: 'Admin', email: 'a@example.com', password: 'pw', confirmPassword: 'pw' }); assert.equal(setup.status, 201); const login = firewall.api('POST', '/api/auth/login', { email: 'a@example.com', password: 'pw' }); const session = login.body.session.id; const created = firewall.api('POST', '/api/policies', { name: 'read', match: { tool: 'x' }, action: 'allow', enabled: true }, session); assert.equal(created.status, 201); assert.equal(firewall.api('PATCH', '/api/policies/read', { enabled: false }, session).status, 200); assert.equal(firewall.api('DELETE', '/api/policies/read', {}, session).status, 204); assert.equal(firewall.api('POST', '/api/mcp-servers', { name: 'db', transport: 'http' }, session).status, 201); const pending = await firewall.handleCall(context({ tool: 'x' })); assert.equal((await firewall.api('POST', `/api/approvals/${pending.approval.id}/reject`, { approver: 'Admin' }, session)).status, 200); assert.equal(firewall.api('POST', '/api/auth/logout', {}, session).status, 204); assert.equal(firewall.api('GET', '/api/policies', {}, session).status, 401); });
test('cli_init_creates_default_yaml', async () => { const { mkdtemp, readFile } = await import('node:fs/promises'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path'); const dir = await mkdtemp(join(tmpdir(), 'mcp-fw-')); const { init } = await import('../src/cli.js'); await init(dir); assert.match(await readFile(join(dir, 'mcp-firewall.yaml'), 'utf8'), /version: 1/); });
test('cli_start_prints_mvp_startup_output', async () => { const firewall = new Firewall({ policies: [{ name: 'x', match: { tool: '*' }, action: 'allow', enabled: true }], servers: [{ name: 'db', transport: 'http' }] }); const output = firewall.startOutput(); assert.match(output, /Policies loaded: 1/); assert.match(output, /MCP servers: 1/); assert.match(output, /Gateway running/); assert.match(output, /http:\/\/localhost:3210/); });
test('cli_headless_starts_real_stdio_gateway_without_dashboard', async () => { const { mkdtemp } = await import('node:fs/promises'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path'); const dir = await mkdtemp(join(tmpdir(), 'mcp-fw-cli-')); const child = spawn(process.execPath, [join(process.cwd(), 'src/cli.js'), 'start', '--headless'], { cwd: dir, stdio: ['pipe', 'pipe', 'pipe'] }); let output = ''; let diagnostics = ''; child.stderr.on('data', (chunk) => { diagnostics += chunk; if (diagnostics.includes('listening on STDIO')) child.stdin.write('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'); }); const status = await new Promise((resolve, reject) => { const timer = setTimeout(() => { child.kill(); reject(new Error('headless gateway did not respond')); }, 3000); child.stdout.on('data', (chunk) => { output += chunk; if (String(chunk).includes('"id":1')) { clearTimeout(timer); child.kill(); resolve(0); } }); child.on('error', reject); }); assert.equal(status, 0); assert.match(diagnostics, /Headless mode: enabled/); assert.match(output, /"protocolVersion":"2025-06-18"/); assert.doesNotMatch(output, /Gateway listening on port/); });
test('cli_init_refuses_existing_yaml', async () => { const { mkdtemp, writeFile } = await import('node:fs/promises'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path'); const dir = await mkdtemp(join(tmpdir(), 'mcp-fw-')); await writeFile(join(dir, 'mcp-firewall.yaml'), 'existing'); const { init } = await import('../src/cli.js'); await assert.rejects(() => init(dir), /already exists/); });
test('cli_headless_starts_without_dashboard', async () => { const { mkdtemp } = await import('node:fs/promises'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path'); const dir = await mkdtemp(join(tmpdir(), 'mcp-fw-cli-proof-')); const child = spawn(process.execPath, [join(process.cwd(), 'src/cli.js'), 'start', '--headless'], { cwd: dir, stdio: ['pipe', 'pipe', 'pipe'] }); let response = ''; child.stdout.on('data', (chunk) => { response += chunk; if (response.includes('protocolVersion')) child.kill(); }); await new Promise((resolve, reject) => { const timer = setTimeout(() => { child.kill(); reject(new Error('headless gateway did not respond')); }, 3000); child.stderr.on('data', (chunk) => { if (String(chunk).includes('listening on STDIO')) child.stdin.write('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'); }); child.stdout.on('data', (chunk) => { if (String(chunk).includes('"id":1')) { clearTimeout(timer); resolve(0); } }); child.on('error', reject); }); assert.match(response, /"protocolVersion":"2025-06-18"/); assert.doesNotMatch(response, /Gateway listening on port/); });
