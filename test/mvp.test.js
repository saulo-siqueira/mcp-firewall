import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { Firewall, createApiServer, createMcpCall } from '../src/index.js';

const context = (overrides = {}) => ({
  agent: 'claude-code', server: 'filesystem', tool: 'filesystem.read',
  arguments: { path: '/tmp/readme' }, ...overrides,
});

test('gateway_identifies_tool_call_context', async () => {
  const firewall = new Firewall();
  const call = createMcpCall(context());
  assert.deepEqual(call, context());
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
  const firewall = new Firewall({ policies: [{ name: 'other', match: { tool: 'other' }, action: 'allow', enabled: true }] });
  assert.equal((await firewall.handleCall(context())).decision, 'DENY');
});

test('policy_precedence_restrictiveness_table', async () => {
  const firewall = new Firewall({ policies: [
    { name: 'allow', match: { tool: 'filesystem.*' }, action: 'allow', enabled: true },
    { name: 'approval', match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true },
    { name: 'deny', match: { tool: 'filesystem.read' }, action: 'deny', enabled: true },
  ] });
  assert.equal((await firewall.evaluate(context())).decision, 'DENY');
});

test('gateway_uses_stdio_transport', async () => {
  const firewall = new Firewall({ servers: [{ name: 'filesystem', transport: 'stdio', handler: async () => 'stdio' }], policies: [{ match: { tool: 'filesystem.read' }, action: 'allow', enabled: true }] });
  assert.equal((await firewall.handleCall(context())).result, 'stdio');
});

test('gateway_uses_streamable_http_transport', async () => {
  const firewall = new Firewall({ servers: [{ name: 'filesystem', transport: 'http', handler: async () => 'http' }], policies: [{ match: { tool: 'filesystem.read' }, action: 'allow', enabled: true }] });
  assert.equal((await firewall.handleCall(context())).result, 'http');
});

test('secret_scanner_redacts_initial_categories_before_forwarding', async () => {
  let received;
  const firewall = new Firewall({ servers: [{ name: 'filesystem', handler: async (call) => { received = call.arguments; return true; } }], policies: [{ match: { tool: 'filesystem.read' }, action: 'allow', enabled: true }] });
  await firewall.handleCall(context({ arguments: { apiKey: 'a', token: 'b', password: 'c', privateKey: 'd', environmentSecret: 'e' } }));
  assert.deepEqual(received, { apiKey: '[REDACTED]', token: '[REDACTED]', password: '[REDACTED]', privateKey: '[REDACTED]', environmentSecret: '[REDACTED]' });
});

test('audit_event_contains_required_fields_for_each_decision', async () => {
  const firewall = new Firewall({ policies: [{ match: { tool: 'filesystem.read' }, action: 'deny', enabled: true }] });
  const event = (await firewall.handleCall(context())).audit;
  for (const key of ['id', 'agent', 'server', 'tool', 'arguments', 'decision', 'policy', 'duration', 'result', 'created_at']) assert.ok(key in event);
});

test('audit_event_never_persists_raw_secret', async () => {
  const firewall = new Firewall({ policies: [{ match: { tool: 'filesystem.read' }, action: 'deny', enabled: true }] });
  const event = (await firewall.handleCall(context({ arguments: { password: 'raw-secret' } }))).audit;
  assert.equal(JSON.stringify(event).includes('raw-secret'), false); assert.equal(event.arguments.password, '[REDACTED]');
});

test('approval_request_starts_pending_with_redacted_context', async () => {
  const firewall = new Firewall({ policies: [{ name: 'approve', match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true }] });
  const result = await firewall.handleCall(context({ arguments: { password: 'secret' } }));
  assert.equal(result.approval.status, 'PENDING'); assert.equal(result.approval.arguments.password, '[REDACTED]');
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
test('auth_expired_or_logged_out_session_is_rejected', async () => { const firewall = new Firewall(); firewall.setupAdmin({ name: 'Admin', email: 'a@example.com', password: 'pw', confirmPassword: 'pw' }); const session = firewall.login('a@example.com', 'pw').session; firewall.logout(session.id); assert.equal(firewall.authorize(session.id), false); });
test('policies_admin_crud_toggle_and_yaml_representation', async () => { const firewall = new Firewall(); firewall.addPolicy({ name: 'read', match: { tool: 'x' }, action: 'allow', enabled: true }); firewall.updatePolicy('read', { enabled: false }); assert.equal(firewall.getPolicy('read').enabled, false); assert.match(firewall.policyYaml('read'), /name: read/); firewall.deletePolicy('read'); assert.equal(firewall.getPolicy('read'), undefined); });
test('mcp_servers_accept_only_mvp_transports', async () => { const firewall = new Firewall(); firewall.addServer({ name: 'db', transport: 'http', url: 'x' }); assert.equal(firewall.servers.get('db').transport, 'http'); assert.throws(() => firewall.addServer({ name: 'x', transport: 'websocket' })); });
test('dashboard_renders_required_metrics_and_sections', async () => { const firewall = new Firewall(); const html = firewall.dashboardHtml(); for (const label of ['Total Tool Calls', 'Allowed', 'Blocked', 'Requires Approval', 'Recent Calls', 'Active Policies', 'Secrets Intercepted', 'Dashboard', 'Tool Calls', 'Policies', 'MCP Servers', 'Approvals', 'Audit Logs', 'Settings']) assert.match(html, new RegExp(label)); assert.match(html, /shell-sidebar/); assert.match(html, /shell-header/); });
test('audit_detail_renders_redacted_call_and_approval_data', async () => { const firewall = new Firewall({ policies: [{ match: { tool: 'filesystem.read' }, action: 'deny', enabled: true }] }); const result = await firewall.handleCall(context({ arguments: { password: 'secret' } })); const html = firewall.auditDetailHtml(result.audit.id); assert.match(html, /\[REDACTED\]/); assert.match(html, /DENY/); });
test('approvals_screen_lists_pending_requests_and_actions', async () => { const firewall = new Firewall({ policies: [{ match: { tool: 'filesystem.read' }, action: 'require_approval', enabled: true }] }); await firewall.handleCall(context()); const html = firewall.approvalsHtml(); assert.match(html, /PENDING/); assert.match(html, /Approve/); assert.match(html, /Reject/); });
test('mcp_servers_screen_renders_allowed_statuses', async () => { const firewall = new Firewall(); firewall.addServer({ name: 'db', transport: 'http', url: 'x' }); const html = firewall.serversHtml(); assert.match(html, /Disconnected/); });
test('admin_screens_render_command_center_sections', async () => { const firewall = new Firewall(); assert.match(firewall.loginHtml(), /Create Admin Account/); assert.match(firewall.toolCallsHtml(), /Tool Calls/); assert.match(firewall.policiesHtml(), /Policies/); assert.match(firewall.settingsHtml(), /Settings/); });
test('admin_screens_expose_loading_and_error_states', async () => { const firewall = new Firewall(); for (const html of [firewall.dashboardHtml(), firewall.toolCallsHtml(), firewall.policiesHtml(), firewall.serversHtml(), firewall.approvalsHtml()]) { assert.match(html, /Loading/); assert.match(html, /Error/); } });
test('cli_init_creates_default_yaml', async () => { const { mkdtemp, readFile } = await import('node:fs/promises'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path'); const dir = await mkdtemp(join(tmpdir(), 'mcp-fw-')); const { init } = await import('../src/cli.js'); await init(dir); assert.match(await readFile(join(dir, 'mcp-firewall.yaml'), 'utf8'), /version: 1/); });
test('cli_start_prints_mvp_startup_output', async () => { const firewall = new Firewall({ policies: [{ name: 'x', match: { tool: '*' }, action: 'allow', enabled: true }], servers: [{ name: 'db', transport: 'http' }] }); const output = firewall.startOutput(); assert.match(output, /Policies loaded: 1/); assert.match(output, /MCP servers: 1/); assert.match(output, /Gateway running/); assert.match(output, /http:\/\/localhost:3210/); });
test('cli_headless_starts_without_dashboard', async () => { const firewall = new Firewall(); assert.equal(firewall.start({ headless: true }).headless, true); const result = spawnSync(process.execPath, ['src/cli.js', 'start', '--headless'], { encoding: 'utf8' }); assert.equal(result.status, 0); assert.match(result.stdout, /Headless mode: enabled/); assert.doesNotMatch(result.stdout, /Dashboard: http/); });
test('cli_init_refuses_existing_yaml', async () => { const { mkdtemp, writeFile } = await import('node:fs/promises'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path'); const dir = await mkdtemp(join(tmpdir(), 'mcp-fw-')); await writeFile(join(dir, 'mcp-firewall.yaml'), 'existing'); const { init } = await import('../src/cli.js'); await assert.rejects(() => init(dir), /already exists/); });
