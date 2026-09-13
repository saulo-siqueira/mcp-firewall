import crypto from 'node:crypto';
import http from 'node:http';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { trace } from '@opentelemetry/api';

const DECISIONS = ['ALLOW', 'DENY', 'REQUIRE_APPROVAL'];
const TRANSPORTS = ['stdio', 'http'];
const APPROVAL_STATES = ['PENDING', 'APPROVED', 'REJECTED'];
const REDACTED = '[REDACTED]';
const stage = (name, work) => { const span = trace.getTracer('mcp-firewall').startSpan(name); try { return work(); } finally { span.end(); } };
const stageAsync = async (name, work) => { const span = trace.getTracer('mcp-firewall').startSpan(name); try { return await work(); } finally { span.end(); } };
const yamlScalar = (value) => typeof value === 'boolean' ? String(value) : JSON.stringify(String(value ?? ''));

export const createMcpCall = ({ agent, server, tool, arguments: args = {} }) => ({
  agent, server, tool, arguments: structuredClone(args),
});

const wildcardMatch = (pattern, value) => {
  if (!pattern || pattern === '*') return true;
  const escaped = String(pattern).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(value);
};

const policyMatches = (policy, call) => Object.entries(policy.match || {}).every(([key, value]) => wildcardMatch(value, call[key]));

const secretKey = (key) => /api.?key|token|password|private.?key|environment.?secret|env.?secret/i.test(key);
const redactString = (value) => String(value).replace(/((?:api[_-]?key|token|password|private[_-]?key|(?:environment|env)[_-]?secret)\s*[=:]\s*)([^\s,;&]+)/gi, '$1[REDACTED]');
const redact = (value) => {
  if (Array.isArray(value)) return value.map(redact);
  if (typeof value === 'string') return redactString(value);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, secretKey(key) ? REDACTED : redact(item)]));
};

const id = (prefix) => `${prefix}_${crypto.randomUUID()}`;
const now = () => new Date().toISOString();
const invokeStdio = (server, call) => new Promise((resolve, reject) => {
  if (!server.command) return reject(new Error('stdio server command is not configured'));
  const child = spawn(server.command, server.args || [], { env: { ...process.env, ...(server.env || {}) } }); let output = ''; let error = '';
  child.stdout.on('data', (chunk) => { output += chunk; }); child.stderr.on('data', (chunk) => { error += chunk; });
  child.on('error', reject); child.on('close', (code) => { if (code !== 0) return reject(new Error(error || `stdio server exited with ${code}`)); try { resolve(JSON.parse(output.trim() || '{}')); } catch { reject(new Error('stdio server returned invalid JSON')); } });
  child.stdin.end(JSON.stringify({ jsonrpc: '2.0', id: id('mcp'), method: 'tools/call', params: { name: call.tool, arguments: call.arguments } }) + '\n');
});
const invokeTarget = async (server, call) => {
  if (server.transport === 'stdio') return invokeStdio(server, call);
  if (!server.url) throw new Error('http server url is not configured');
  if (!server.sessionId) { const initialized = await fetch(server.url, { method: 'POST', headers: { accept: 'application/json, text/event-stream', 'content-type': 'application/json', 'MCP-Protocol-Version': '2025-06-18', ...(server.headers || {}) }, body: JSON.stringify({ jsonrpc: '2.0', id: id('mcp'), method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'mcp-firewall', version: '0.1.0' } } }) }); if (!initialized.ok) throw new Error(`http MCP initialize returned ${initialized.status}`); server.sessionId = initialized.headers.get('mcp-session-id') || undefined; if (server.sessionId) await fetch(server.url, { method: 'POST', headers: { accept: 'application/json, text/event-stream', 'content-type': 'application/json', 'MCP-Protocol-Version': '2025-06-18', 'Mcp-Session-Id': server.sessionId, ...(server.headers || {}) }, body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }) }); }
  const response = await fetch(server.url, { method: 'POST', headers: { accept: 'application/json, text/event-stream', 'content-type': 'application/json', 'MCP-Protocol-Version': '2025-06-18', ...(server.sessionId ? { 'Mcp-Session-Id': server.sessionId } : {}), ...(server.headers || {}) }, body: JSON.stringify({ jsonrpc: '2.0', id: id('mcp'), method: 'tools/call', params: { name: call.tool, arguments: call.arguments } }) });
  if (!response.ok) throw new Error(`http MCP server returned ${response.status}`); const sessionId = response.headers.get('mcp-session-id'); if (sessionId) server.sessionId = sessionId; const text = await response.text(); if (response.headers.get('content-type')?.includes('text/event-stream')) { const events = text.split(/\r?\n\r?\n/).flatMap((block) => block.split(/\r?\n/).filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trim())).filter(Boolean); return JSON.parse(events.at(-1) || '{}'); } return JSON.parse(text || '{}');
};

export const parseConfigYaml = (source) => {
  const config = { policies: [], mcp_servers: [] }; let section = null; let item = null; let nested = null; let nestedIndent = 0;
  for (const raw of String(source).split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, ''); const trimmed = line.trim(); if (!trimmed || trimmed === 'version: 1') continue;
    if (/^(policies|mcp_servers):\s*$/.test(trimmed)) { section = trimmed.slice(0, -1); item = null; nested = null; continue; }
    if (trimmed.startsWith('- ')) { if (!section) continue; item = {}; config[section].push(item); nested = null; nestedIndent = 0; const pair = trimmed.slice(2).split(/:\s*/, 2); if (pair[0] && pair[1] !== undefined) item[pair[0]] = parseYamlScalar(pair[1]); continue; }
    if (!item || !trimmed.includes(':')) continue; const [key, ...rest] = trimmed.split(':'); const value = rest.join(':').trim();
    if (!value) { nested = key.trim(); nestedIndent = line.search(/\S/); item[nested] = {}; continue; }
    if (nested && line.search(/\S/) > nestedIndent) item[nested][key.trim()] = parseYamlScalar(value); else { nested = null; item[key.trim()] = parseYamlScalar(value); }
  }
  if (!/^\s*version:\s*1\s*$/m.test(String(source))) throw new Error('configuration version must be 1');
  for (const policy of config.policies) { if (!policy.name || !policy.action || !DECISIONS.includes(String(policy.action).toUpperCase())) throw new Error('invalid policy configuration'); }
  for (const server of config.mcp_servers) { if (!server.name || !TRANSPORTS.includes(server.transport || 'stdio')) throw new Error('invalid MCP server configuration'); }
  return config;
};
const parseYamlScalar = (value) => { const v = String(value).trim(); if (v === 'true') return true; if (v === 'false') return false; if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1); return v; };
export const loadConfigFile = (file, options = {}) => { const config = parseConfigYaml(readFileSync(file, 'utf8')); return new Firewall({ ...options, configPath: file, policies: config.policies, servers: config.mcp_servers, configAuthoritative: true }); };
export const handleMcpMessage = async (firewall, message, gatewayContext = {}) => {
  const params = message.params || {};
  if (message.method === 'initialize') return { protocolVersion: params.protocolVersion || '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'mcp-firewall', version: '0.1.0' } };
  if (message.method === 'notifications/initialized') return null;
  if (message.method === 'tools/list') return { tools: [] };
  if (message.method !== 'tools/call') return { error: { code: -32601, message: 'method not found' } };
  const result = await firewall.handleCall({ agent: params.agent || message.agent || gatewayContext.agent, server: params.server || gatewayContext.server, tool: params.name || params.tool, arguments: params.arguments || {} });
  return result.error ? { error: { code: -32000, message: result.error.message, data: result } } : result;
};
export const startStdioGateway = (firewall, input = process.stdin, output = process.stdout, gatewayContext = {}) => { let buffer = ''; input.setEncoding('utf8'); input.on('data', async (chunk) => { buffer += chunk; const lines = buffer.split(/\r?\n/); buffer = lines.pop(); for (const line of lines.filter(Boolean)) { try { const message = JSON.parse(line); const payload = await handleMcpMessage(firewall, message, gatewayContext); if (message.id !== undefined && payload !== null) { const response = payload.error ? { jsonrpc: '2.0', id: message.id, error: payload.error } : { jsonrpc: '2.0', id: message.id, result: payload }; output.write(`${JSON.stringify(response)}\n`); } } catch (error) { output.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: error.message } })}\n`); } } }); return firewall; };

export class Firewall {
  constructor({ policies = [], servers = [], approvalAvailable = true, storagePath = null, configPath = null, configAuthoritative = false } = {}) {
    this.storagePath = storagePath;
    this.configPath = configPath;
    this.configAuthoritative = configAuthoritative;
    this.policies = new Map(); this.servers = new Map(); this.users = new Map(); this.sessions = new Map();
    this.approvals = new Map(); this.audit = new Map(); this.approvalAvailable = approvalAvailable;
    if (this.storagePath && existsSync(this.storagePath)) { this.restore(JSON.parse(readFileSync(this.storagePath, 'utf8'))); if (this.configAuthoritative) { this.policies.clear(); this.servers.clear(); } }
    policies.forEach((policy) => { if (!this.policies.has(policy.name)) this.addPolicy(policy); });
    servers.forEach((server) => { if (!this.servers.has(server.name)) this.addServer(server); });
  }

  persist() { if (this.storagePath) writeFileSync(this.storagePath, JSON.stringify({ policies: [...this.policies.values()], servers: [...this.servers.values()].map(({ handler, ...server }) => server), users: [...this.users.values()], sessions: [...this.sessions.values()], approvals: [...this.approvals.values()], audit: [...this.audit.values()] }, null, 2)); if (this.configPath) { try { writeFileSync(this.configPath, this.configYaml()); } catch { /* read-only config mounts keep API state in storage */ } } }
  configYaml() { const policies = [...this.policies.values()].map((p) => `  - name: ${yamlScalar(p.name)}\n    match:\n${Object.entries(p.match || {}).map(([key, value]) => `      ${key}: ${yamlScalar(value)}`).join('\n')}\n    action: ${yamlScalar(p.action.toLowerCase())}\n    enabled: ${p.enabled}`).join('\n'); const servers = [...this.servers.values()].map((s) => `  - name: ${yamlScalar(s.name)}\n    transport: ${yamlScalar(s.transport)}\n    ${s.transport === 'http' ? `url: ${yamlScalar(s.url)}` : `command: ${yamlScalar(s.command)}`}`).join('\n'); return `version: 1\npolicies:\n${policies || ''}\nmcp_servers:\n${servers || ''}\n`; }
  restore(state) { for (const policy of state.policies || []) this.policies.set(policy.name, policy); for (const server of state.servers || []) this.servers.set(server.name, server); for (const user of state.users || []) this.users.set(user.email, user); for (const session of state.sessions || []) this.sessions.set(session.id, session); for (const approval of state.approvals || []) this.approvals.set(approval.id, approval); for (const event of state.audit || []) this.audit.set(event.id, event); }

  addPolicy(input) {
    const name = input?.name || id('policy');
    if (this.policies.has(name)) { const error = new Error('policy already exists'); error.code = 'CONFLICT'; throw error; }
    if (!DECISIONS.includes(input.action.toUpperCase())) throw new Error('invalid policy action');
    const policy = { enabled: true, ...input, name, action: input.action.toUpperCase() };
    this.policies.set(policy.name, policy); this.persist(); return policy;
  }

  updatePolicy(name, changes) { const current = this.policies.get(name); if (!current) throw new Error('policy not found'); if (changes.action !== undefined && !DECISIONS.includes(String(changes.action).toUpperCase())) throw new Error('invalid policy action'); const next = { ...current, ...changes, action: changes.action ? String(changes.action).toUpperCase() : current.action }; this.policies.set(name, next); this.persist(); return next; }
  getPolicy(name) { return this.policies.get(name); }
  deletePolicy(name) { const deleted = this.policies.delete(name); if (deleted) this.persist(); return deleted; }
  policyYaml(name) { const p = this.getPolicy(name); if (!p) throw new Error('policy not found'); const match = Object.entries(p.match || {}).map(([key, value]) => `      ${key}: ${yamlScalar(value)}`).join('\n') || '      tool: "*"'; return `version: 1\npolicies:\n  - name: ${yamlScalar(p.name)}\n    match:\n${match}\n    action: ${yamlScalar(p.action.toLowerCase())}\n    enabled: ${p.enabled}\n`; }

  addServer(input) {
    const transport = input?.transport || 'stdio';
    if (!input?.name || !TRANSPORTS.includes(transport)) throw new Error('transport must be stdio or http');
    if (input.status !== undefined && !['Connected', 'Disconnected', 'Error'].includes(input.status)) throw new Error('invalid server status');
    if (this.servers.has(input.name)) { const error = new Error('server already exists'); error.code = 'CONFLICT'; throw error; }
    const server = { status: input.status || 'Disconnected', transport, ...input };
    this.servers.set(server.name, server); this.persist(); return server;
  }
  updateServer(name, changes) { const current = this.servers.get(name); if (!current) throw new Error('server not found'); const transport = changes.transport || current.transport; if (!TRANSPORTS.includes(transport)) throw new Error('transport must be stdio or http'); if (changes.status !== undefined && !['Connected', 'Disconnected', 'Error'].includes(changes.status)) throw new Error('invalid server status'); const next = { ...current, ...changes, name, transport }; this.servers.set(name, next); this.persist(); return next; }
  deleteServer(name) { const deleted = this.servers.delete(name); if (deleted) this.persist(); return deleted; }

  evaluate(input) {
    const call = createMcpCall(input); const candidates = stage('policy.match', () => [...this.policies.values()].filter((p) => p.enabled && policyMatches(p, call)));
    const rank = { ALLOW: 1, REQUIRE_APPROVAL: 2, DENY: 3 };
    candidates.sort((a, b) => rank[b.action] - rank[a.action]);
    const policy = candidates[0]; return { decision: policy?.action || 'DENY', policy: policy?.name || null, call };
  }

  async handleCall(input) {
    const evaluated = stage('policy.evaluate', () => this.evaluate(input)); const call = { ...evaluated.call, arguments: stage('secret.scan', () => redact(evaluated.call.arguments)) };
    const started = Date.now(); const base = input._audit_id && this.audit.get(input._audit_id) ? this.audit.get(input._audit_id) : { id: crypto.randomUUID(), agent: call.agent, server: call.server, tool: call.tool, arguments: call.arguments, decision: evaluated.decision, policy: evaluated.policy, duration: 0, result: null, created_at: now() };
    const finish = (result, error = null) => { base.duration = Date.now() - started; base.result = result ?? error?.message ?? null; this.audit.set(base.id, base); this.persist(); return { ...result && typeof result === 'object' ? result : {}, decision: evaluated.decision, result, error, audit: base }; };
    if (evaluated.decision === 'DENY') return finish(null, { code: 'POLICY_DENIED', message: 'MCP call denied by policy' });
    if (evaluated.decision === 'REQUIRE_APPROVAL' && !input._approved) {
      if (!this.approvalAvailable) { const unavailable = stage('approval.check', () => finish(null, { code: 'APPROVAL_UNAVAILABLE', message: 'approval mechanism unavailable' })); unavailable.decision = 'DENY'; return unavailable; }
      const approval = { id: id('approval'), status: 'PENDING', agent: call.agent, server: call.server, tool: call.tool, arguments: call.arguments, requested_at: now(), policy: evaluated.policy, call };
      approval.audit_id = base.id; this.approvals.set(approval.id, approval); this.persist(); return finish(null, null) && { decision: 'REQUIRE_APPROVAL', approval, audit: base };
    }
    const server = this.servers.get(call.server); let result;
    try { if (!server) throw new Error('MCP server not configured'); result = await stageAsync('mcp.forward', () => server.handler ? server.handler(call) : invokeTarget(server, call)); return finish(result); }
    catch (error) { return finish(null, { code: 'TARGET_ERROR', message: error.message }); }
  }

  async approve(approvalId, approver) {
    const approval = this.approvals.get(approvalId); if (!approval || approval.status !== 'PENDING') throw new Error('approval is not pending');
    approval.status = 'APPROVED'; approval.approved_by = approver; approval.approved_at = now(); this.persist();
    const result = await this.handleCall({ ...approval.call, _approved: true, _audit_id: approval.audit_id });
    const audit = this.audit.get(approval.audit_id); if (audit) { audit.decision = 'APPROVED'; audit.approved_by = approver; audit.approved_at = approval.approved_at; this.persist(); }
    return { ...result, approval };
  }

  reject(approvalId, rejecter) { const approval = this.approvals.get(approvalId); if (!approval || approval.status !== 'PENDING') throw new Error('approval is not pending'); approval.status = 'REJECTED'; approval.rejected_by = rejecter; approval.rejected_at = now(); const audit = this.audit.get(approval.audit_id); if (audit) { audit.decision = 'DENY'; audit.rejected_by = rejecter; audit.rejected_at = approval.rejected_at; } this.persist(); return { decision: 'DENY', approval }; }

  setupAdmin({ name, email, password, confirmPassword }) {
    if (this.users.size) { const error = new Error('admin already exists'); error.code = 'CONFLICT'; throw error; }
    if (!name || !email || !password || password !== confirmPassword) throw new Error('invalid admin data');
    const user = { id: id('user'), name, email, password_hash: crypto.scryptSync(password, 'mcp-firewall', 32).toString('hex'), role: 'ADMIN', created_at: now(), updated_at: now() };
    this.users.set(email, user); this.persist(); return { ...user };
  }

  login(email, password) {
    const user = this.users.get(email); const hash = user && crypto.scryptSync(password, 'mcp-firewall', 32).toString('hex');
    if (!user || hash !== user.password_hash) throw new Error('invalid credentials');
    const session = { id: id('session'), userId: user.id, created_at: now(), expires_at: Date.now() + 8 * 60 * 60 * 1000 }; this.sessions.set(session.id, session); this.persist(); return { user: { ...user, password_hash: undefined }, session };
  }

  authorize(sessionId) { const session = this.sessions.get(sessionId); if (!session || session.expires_at <= Date.now()) { if (session) { this.sessions.delete(sessionId); this.persist(); } return false; } return true; }
  sessionUser(sessionId) { const session = this.sessions.get(sessionId); return [...this.users.values()].find((user) => user.id === session?.userId); }
  logout(sessionId) { this.sessions.delete(sessionId); this.persist(); }

  api(method, path, body = {}, sessionId) {
    if (method === 'POST' && path === '/api/auth/setup') {
      try { return { status: 201, body: { user: this.setupAdmin(body) } }; }
      catch (error) { return { status: error.code === 'CONFLICT' ? 409 : 422, body: { error: error.message } }; }
    }
    if (method === 'POST' && path === '/api/auth/login') {
      try { return { status: 200, body: this.login(body.email, body.password) }; }
      catch (error) { return { status: 401, body: { error: 'INVALID_CREDENTIALS' } }; }
    }
    if (method === 'POST' && path === '/api/auth/logout') {
      if (!this.authorize(sessionId)) return { status: 401, body: { error: 'UNAUTHORIZED' } };
      this.logout(sessionId); return { status: 204, body: null };
    }
    const privateRoute = path.startsWith('/api/');
    if (privateRoute && !this.authorize(sessionId)) return { status: 401, body: { error: 'UNAUTHORIZED' } };
    const collections = { '/api/policies': [...this.policies.values()], '/api/mcp-servers': [...this.servers.values()], '/api/tool-calls': [...this.audit.values()], '/api/audit-logs': [...this.audit.values()], '/api/approvals': [...this.approvals.values()] };
    if (method === 'GET' && collections[path]) return { status: 200, body: collections[path] };
    if (method === 'POST' && path === '/api/policies') {
      try { return { status: 201, body: this.addPolicy(body) }; }
      catch (error) { return { status: error.code === 'CONFLICT' ? 409 : 422, body: { error: error.message } }; }
    }
    const policyPath = path.match(/^\/api\/policies\/([^/]+)$/);
    if (policyPath && method === 'PATCH') {
      try { return { status: 200, body: this.updatePolicy(decodeURIComponent(policyPath[1]), body) }; }
      catch (error) { return { status: error.message === 'policy not found' ? 404 : 422, body: { error: error.message } }; }
    }
    if (policyPath && method === 'DELETE') {
      if (!this.deletePolicy(decodeURIComponent(policyPath[1]))) return { status: 404, body: { error: 'NOT_FOUND' } };
      return { status: 204, body: null };
    }
    if (method === 'POST' && path === '/api/mcp-servers') {
      try { return { status: 201, body: this.addServer(body) }; }
      catch (error) { return { status: error.code === 'CONFLICT' ? 409 : 422, body: { error: error.message } }; }
    }
    const serverPath = path.match(/^\/api\/mcp-servers\/([^/]+)$/);
    if (serverPath && method === 'PATCH') { try { return { status: 200, body: this.updateServer(decodeURIComponent(serverPath[1]), body) }; } catch (error) { return { status: error.message === 'server not found' ? 404 : 422, body: { error: error.message } }; } }
    if (serverPath && method === 'DELETE') { if (!this.deleteServer(decodeURIComponent(serverPath[1]))) return { status: 404, body: { error: 'NOT_FOUND' } }; return { status: 204, body: null }; }
    const approvalPath = path.match(/^\/api\/approvals\/([^/]+)\/(approve|reject)$/);
    if (approvalPath && method === 'POST') {
      const approvalId = decodeURIComponent(approvalPath[1]);
      if (approvalPath[2] === 'reject') {
        try { return { status: 200, body: this.reject(approvalId, this.sessionUser(sessionId)?.name || 'admin') }; }
        catch (error) { return { status: error.message === 'approval is not pending' ? 409 : 404, body: { error: error.message === 'approval is not pending' ? 'APPROVAL_NOT_PENDING' : 'NOT_FOUND' } }; }
      }
      return this.approve(approvalId, this.sessionUser(sessionId)?.name || 'admin')
        .then((result) => ({ status: 200, body: result }))
        .catch((error) => ({ status: error.message === 'approval is not pending' ? 409 : 404, body: { error: error.message === 'approval is not pending' ? 'APPROVAL_NOT_PENDING' : 'NOT_FOUND' } }));
    }
    return { status: 404, body: { error: 'NOT_FOUND' } };
  }

  start({ headless = false } = {}) { return { headless, running: true, dashboard: headless ? null : 'http://localhost:3210' }; }
  startOutput() { return `MCP Firewall v${'0.1.0'}\n\nPolicies loaded: ${this.policies.size}\nMCP servers: ${this.servers.size}\n\nGateway running.\nDashboard: http://localhost:3210`; }

  dashboardHtml() { const events = [...this.audit.values()]; const allowed = events.filter((x) => x.decision === 'ALLOW').length; const blocked = events.filter((x) => x.decision === 'DENY').length; const approvals = events.filter((x) => x.decision === 'REQUIRE_APPROVAL').length; const recent = events.slice(-5).reverse().map((x) => `<article>${x.tool} · ${x.decision}</article>`).join('') || '<p class="empty">No tool calls recorded yet.</p>'; const active = [...this.policies.values()].filter((x) => x.enabled).map((x) => `<article>${x.name} · ${x.action}</article>`).join('') || '<p class="empty">No active policies.</p>'; const counts = Object.entries(events.reduce((all, event) => ({ ...all, [event.tool]: (all[event.tool] || 0) + 1 }), {})).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([tool, count]) => `<article>${tool} · ${count}</article>`).join('') || '<p class="empty">No tools used yet.</p>'; const timeline = events.slice(-10).map((x) => `<article>${x.created_at} · ${x.decision}</article>`).join('') || '<p class="empty">No activity yet.</p>'; const secrets = events.filter((x) => JSON.stringify(x.arguments).includes(REDACTED)).length; return shell('Dashboard', `<h1>Dashboard</h1><section class="metrics"><b>Total Tool Calls ${events.length}</b><b>Allowed ${allowed}</b><b>Blocked ${blocked}</b><b>Requires Approval ${approvals}</b></section><section class="workspace-grid"><div><h2>Recent Calls</h2>${recent}<h2>Calls over time</h2>${timeline}</div><div><h2>Active Policies</h2>${active}<h2>Most used tools</h2>${counts}</div><div><h2>Secrets Intercepted</h2><p>${secrets}</p></div></section>`); }
  auditDetailHtml(auditId) { const event = this.audit.get(auditId); return shell('Audit Logs', `<h1>Audit Logs</h1><pre>${escapeHtml(JSON.stringify(event, null, 2))}</pre>`); }
  approvalsHtml() { return shell('Approvals', `<h1>Approvals</h1>${[...this.approvals.values()].map((a) => `<article><strong>${a.status}</strong> ${a.tool} · ${a.agent} · ${a.server} · ${a.policy || ''}<time>${a.requested_at}</time><pre>${escapeHtml(JSON.stringify(a.arguments, null, 2))}</pre><button data-approval="${a.id}" data-action="approve">Approve</button><button data-approval="${a.id}" data-action="reject">Reject</button></article>`).join('') || '<p class="empty">No pending approvals.</p>'}`); }
  serversHtml() { return shell('MCP Servers', `<h1>MCP Servers</h1>${[...this.servers.values()].map((s) => `<article data-server-name="${escapeHtml(s.name)}"><form class="server-edit" data-server-name="${escapeHtml(s.name)}"><input name="name" value="${escapeHtml(s.name)}" disabled><select name="transport"><option value="stdio" ${s.transport === 'stdio' ? 'selected' : ''}>stdio</option><option value="http" ${s.transport === 'http' ? 'selected' : ''}>http</option></select><input name="target" value="${escapeHtml(s.transport === 'http' ? s.url || '' : s.command || '')}" required><button>Save</button><button type="button" data-delete-server="${escapeHtml(s.name)}">Delete</button></form><strong>${escapeHtml(s.status)}</strong></article>`).join('') || '<p class="empty">No MCP servers configured.</p>'}<form id="server-create"><input name="name" placeholder="Name" required><select name="transport"><option value="stdio">stdio</option><option value="http">http</option></select><input name="target" placeholder="Command or URL" required><button>Add MCP Server</button></form>`); }
  loginHtmlLegacy() { return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Create Admin Account</title><style>body{margin:0;background:#fcfaf7;color:#423d38;font:14px ui-sans-serif,system-ui}.login{min-height:100vh;display:grid;grid-template-columns:1fr 1fr}.visual{padding:64px;background:#fff;display:grid;place-content:center}.panel{background:#ff6b00;padding:64px;display:grid;place-content:center}.card{background:#fff;border-radius:8px;padding:32px;min-width:280px}input{display:block;width:100%;margin:8px 0;padding:10px;border:1px solid #e3e0dd;border-radius:6px}button{background:#fe6e00;color:#fff;border:0;padding:10px 16px;border-radius:6px}@media(max-width:700px){.login{grid-template-columns:1fr}.visual{display:none}}</style></head><body><main class="login"><section class="visual"><h1>MCP Firewall</h1><p>Policy control between agents and tools.</p></section><section class="panel"><form class="card"><h2>Create Admin Account</h2><label>Name<input name="name"></label><label>Email<input name="email" type="email"></label><label>Password<input name="password" type="password"></label><label>Confirm Password<input name="confirmPassword" type="password"></label><button>Create Admin</button></form></section></main></body></html>`; }
  loginHtml() { return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>MCP Firewall Admin</title><style>body{margin:0;background:#fcfaf7;color:#423d38;font:14px ui-sans-serif,system-ui}.login{min-height:100vh;display:grid;grid-template-columns:1fr 1fr}.visual{padding:64px;background:#fff;display:grid;place-content:center}.panel{background:#ff6b00;padding:64px;display:grid;place-content:center}.card{background:#fff;border-radius:8px;padding:32px;min-width:280px}input{display:block;width:100%;margin:8px 0;padding:10px;border:1px solid #e3e0dd;border-radius:6px}button{background:#fe6e00;color:#fff;border:0;padding:10px 16px;border-radius:6px}@media(max-width:700px){.login{grid-template-columns:1fr}.visual{display:none}}</style></head><body><main class="login"><section class="visual"><h1>MCP Firewall</h1><p>Policy control between agents and tools.</p></section><section class="panel"><form class="card" id="admin-setup"><h2>Create Admin Account</h2><input name="name" placeholder="Name" required><input name="email" type="email" placeholder="Email" required><input name="password" type="password" placeholder="Password" required><input name="confirmPassword" type="password" placeholder="Confirm Password" required><button>Create Admin</button></form><form class="card" id="admin-login"><h2>Sign in</h2><input name="email" type="email" placeholder="Email" required><input name="password" type="password" placeholder="Password" required><button>Sign in</button></form></section></main><script>const submit=async(form,path)=>{form.addEventListener('submit',async(event)=>{event.preventDefault();const body=Object.fromEntries(new FormData(form));const response=await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const data=await response.json();if(!response.ok)return alert(data.error||'Request failed');if(data.session)localStorage.setItem('mcp-firewall-session',data.session.id);location.href='/api/dashboard';});};submit(document.querySelector('#admin-setup'),'/api/auth/setup');submit(document.querySelector('#admin-login'),'/api/auth/login');</script></body></html>`; }
  toolCallsHtml() { return shell('Tool Calls', `<h1>Tool Calls</h1>${[...this.audit.values()].map((event) => `<article><strong>${event.created_at}</strong> · ${event.agent} · ${event.tool} · ${event.server} · ${event.decision} · ${event.result ?? '-'} · ${event.duration}ms<details><summary>Details</summary><pre>${escapeHtml(JSON.stringify(event, null, 2))}</pre></details></article>`).join('') || '<p class="empty">No tool calls recorded yet.</p>'}`); }
  policiesHtml() { return shell('Policies', `<h1>Policies</h1>${[...this.policies.values()].map((policy) => `<article><strong>${policy.name}</strong> · ${policy.action} · ${policy.enabled ? 'Enabled' : 'Disabled'} <form class="policy-edit" data-policy-name="${policy.name}"><input name="agent" value="${policy.match?.agent || ''}" placeholder="Agent"><input name="server" value="${policy.match?.server || ''}" placeholder="Server"><input name="tool" value="${policy.match?.tool || ''}" placeholder="Tool" required><select name="action"><option ${policy.action === 'ALLOW' ? 'selected' : ''} value="allow">Allow</option><option ${policy.action === 'DENY' ? 'selected' : ''} value="deny">Deny</option><option ${policy.action === 'REQUIRE_APPROVAL' ? 'selected' : ''} value="require_approval">Require approval</option></select><button>Save</button></form><button data-toggle-policy="${policy.name}">${policy.enabled ? 'Disable' : 'Enable'}</button><button data-delete-policy="${policy.name}">Delete</button><details><summary>YAML</summary><pre>${escapeHtml(this.policyYaml(policy.name))}</pre></details></article>`).join('') || '<p class="empty">No policies configured.</p>'}<form id="policy-create"><input name="name" placeholder="Name" required><input name="agent" placeholder="Agent"><input name="server" placeholder="Server"><input name="tool" placeholder="Tool match" required><select name="action"><option value="allow">Allow</option><option value="deny">Deny</option><option value="require_approval">Require approval</option></select><button>Create policy</button></form>`); }
  settingsHtml() { return shell('Settings', `<h1>Settings</h1><p>Gateway configuration and session settings.</p>`); }
  renderView(view = 'dashboard') {
    const views = { dashboard: () => this.dashboardHtml(), 'tool-calls': () => this.toolCallsHtml(), policies: () => this.policiesHtml(), 'mcp-servers': () => this.serversHtml(), approvals: () => this.approvalsHtml(), 'audit-logs': () => this.auditDetailHtml([...this.audit.keys()][0]), settings: () => this.settingsHtml(), login: () => this.loginHtml() };
    return (views[view] || views.dashboard)();
  }
}

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const shell = (active, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${active}</title><style>
  :root{font-family:ui-sans-serif,system-ui,sans-serif;color:#423d38;background:#fcfaf7}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#fcfaf7} .app{display:grid;grid-template-columns:256px 1fr;min-height:100vh}.shell-sidebar,.shell-header{background:rgba(0,0,0,.70);color:#fff;border-color:rgba(255,255,255,.1)}.shell-sidebar{padding:24px 16px}.brand{font-size:18px;font-weight:700;letter-spacing:-.02em;margin:0 0 32px}.nav{display:grid;gap:8px}.nav a{color:rgba(255,255,255,.7);text-decoration:none;padding:8px 12px;border-radius:8px;font-size:13px;font-weight:700}.nav a.active,.nav a:hover{background:#fe6e00;color:#fff}.main{min-width:0}.shell-header{height:64px;padding:0 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.1);backdrop-filter:blur(12px)}.shell-header small{color:rgba(255,255,255,.7)}.content{max-width:1400px;padding:32px;margin:0 auto}h1{font-size:24px;margin:0 0 24px}h2{font-size:18px;margin:0 0 16px}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:32px}.metrics b{background:#fff;border:1px solid #e3e0dd;border-radius:12px;padding:24px;display:grid;gap:8px;font-size:14px}.metrics b::first-line{font-size:20px}.workspace-grid{display:grid;grid-template-columns:2fr 1fr;gap:24px}.workspace-grid>div{background:#fff;border:1px solid #e3e0dd;border-radius:12px;padding:24px;min-height:150px}.workspace-grid>div:first-child{grid-row:span 2}.empty{color:#797067}article{background:#fff;border:1px solid #e3e0dd;border-radius:8px;padding:16px;margin:8px 0}button{background:#fe6e00;color:#fff;border:0;padding:8px 12px;margin:8px;border-radius:6px}pre{white-space:pre-wrap;background:#fff;padding:24px;border-radius:12px;border:1px solid #e3e0dd}@media(max-width:800px){.app{grid-template-columns:1fr}.shell-sidebar{padding:16px}.nav{display:flex;overflow:auto}.content{padding:24px 16px}.metrics,.workspace-grid{grid-template-columns:1fr}.workspace-grid>div:first-child{grid-row:auto}}
  </style></head><body><div class="app"><aside class="shell-sidebar"><p class="brand">MCP Firewall</p><nav class="nav">${['Dashboard','Tool Calls','Policies','MCP Servers','Approvals','Audit Logs','Settings'].map((item) => { const view = item.toLowerCase().replaceAll(' ', '-'); return `<a class="${item === active ? 'active' : ''}" href="/api/dashboard?view=${view}">${item}</a>`; }).join('')}</nav></aside><div class="main"><header class="shell-header"><strong>${active}</strong><small>ADMIN · LOCAL GATEWAY</small></header><main class="content"><div class="state" data-state="loading" hidden>Loading</div><div class="state error" data-state="error" hidden>Error loading data</div>${body}</main></div></div><script>const sessionHeaders=()=>({'content-type':'application/json'});const matchData=(data)=>Object.fromEntries(Object.entries({agent:data.agent,server:data.server,tool:data.tool}).filter(([,value])=>value));document.querySelectorAll('[data-approval]').forEach((button)=>button.addEventListener('click',async()=>{if(!confirm(button.dataset.action+' this request?'))return;await fetch('/api/approvals/'+button.dataset.approval+'/'+button.dataset.action,{method:'POST',headers:sessionHeaders(),body:JSON.stringify({approver:'Admin'})});location.reload();}));document.querySelectorAll('[data-toggle-policy]').forEach((button)=>button.addEventListener('click',async()=>{await fetch('/api/policies/'+encodeURIComponent(button.dataset.togglePolicy),{method:'PATCH',headers:sessionHeaders(),body:JSON.stringify({enabled:button.textContent==='Enable'})});location.reload();}));document.querySelectorAll('[data-delete-policy]').forEach((button)=>button.addEventListener('click',async()=>{if(confirm('Delete policy?')){await fetch('/api/policies/'+encodeURIComponent(button.dataset.deletePolicy),{method:'DELETE',headers:sessionHeaders()});location.reload();}}));document.querySelectorAll('.policy-edit').forEach(form=>form.addEventListener('submit',async(e)=>{e.preventDefault();const data=Object.fromEntries(new FormData(form));await fetch('/api/policies/'+encodeURIComponent(form.dataset.policyName),{method:'PATCH',headers:sessionHeaders(),body:JSON.stringify({match:matchData(data),action:data.action})});location.reload();}));const form=document.querySelector('#policy-create');if(form)form.addEventListener('submit',async(e)=>{e.preventDefault();const data=Object.fromEntries(new FormData(form));await fetch('/api/policies',{method:'POST',headers:sessionHeaders(),body:JSON.stringify({name:data.name,match:matchData(data),action:data.action,enabled:true})});location.reload();});const serverForm=document.querySelector('#server-create');if(serverForm)serverForm.addEventListener('submit',async(e)=>{e.preventDefault();const data=Object.fromEntries(new FormData(serverForm));const config=data.transport==='http'?{url:data.target}:{command:data.target};await fetch('/api/mcp-servers',{method:'POST',headers:sessionHeaders(),body:JSON.stringify({name:data.name,transport:data.transport,...config})});location.reload();});document.querySelectorAll('.server-edit').forEach(form=>form.addEventListener('submit',async(e)=>{e.preventDefault();const data=Object.fromEntries(new FormData(form));const config=data.transport==='http'?{url:data.target}:{command:data.target};await fetch('/api/mcp-servers/'+encodeURIComponent(form.dataset.serverName),{method:'PATCH',headers:sessionHeaders(),body:JSON.stringify({transport:data.transport,...config})});location.reload();}));document.querySelectorAll('[data-delete-server]').forEach((button)=>button.addEventListener('click',async()=>{if(confirm('Delete server?')){await fetch('/api/mcp-servers/'+encodeURIComponent(button.dataset.deleteServer),{method:'DELETE',headers:sessionHeaders()});location.reload();}}));</script></body></html>`;
const page = (title, body) => shell(title, body);

const readJsonBody = (request) => new Promise((resolve, reject) => {
  let data = '';
  request.on('data', (chunk) => { data += chunk; });
  request.on('end', () => { if (!data) return resolve({}); try { resolve(JSON.parse(data)); } catch { reject(new Error('invalid JSON')); } });
  request.on('error', reject);
});

export function createApiServer(firewall, { port = 3210 } = {}) {
  return http.createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || `localhost:${port}`}`);
    const cookies = Object.fromEntries(String(request.headers.cookie || '').split(';').map((item) => item.trim().split('=').map(decodeURIComponent)).filter(([key, value]) => key && value));
    const sessionId = request.headers['x-session-id'] || String(request.headers.authorization || '').replace(/^Bearer\s+/i, '') || cookies.session || undefined;
    if (request.method === 'GET' && url.pathname === '/api/dashboard') { const view = url.searchParams.get('view') || 'dashboard'; if (view === 'login' || (firewall.users.size === 0 && !sessionId)) { response.writeHead(200, { 'content-type': 'text/html' }); response.end(firewall.loginHtml()); return; } if (!firewall.authorize(sessionId)) { response.writeHead(401, { 'content-type': 'application/json' }); response.end(JSON.stringify({ error: 'UNAUTHORIZED', login: '/api/dashboard?view=login' })); return; } response.writeHead(200, { 'content-type': 'text/html' }); response.end(firewall.renderView(view)); return; }
    let body = {};
    try { if (request.method !== 'GET' && request.method !== 'HEAD') body = await readJsonBody(request); }
    catch { response.writeHead(400, { 'content-type': 'application/json' }); response.end(JSON.stringify({ error: 'INVALID_JSON' })); return; }
    if (request.method === 'POST' && (url.pathname === '/mcp' || url.pathname === '/mcp/' || url.pathname === '/mcp/tools/call')) {
      try {
        const result = url.pathname === '/mcp/tools/call' ? await firewall.handleCall(body) : await handleMcpMessage(firewall, body, { agent: request.headers['mcp-agent'], server: request.headers['mcp-server'] });
        if (body.method && result?.error && body.method !== 'tools/call') { response.writeHead(result.error.code === -32601 ? 404 : 400, { 'content-type': 'application/json' }); response.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: result.error })); return; }
        const status = result.decision === 'ALLOW' ? 200 : result.decision === 'REQUIRE_APPROVAL' ? 202 : result.error?.code === 'APPROVAL_UNAVAILABLE' ? 409 : 403;
        response.writeHead(status, { 'content-type': 'application/json', 'MCP-Protocol-Version': '2025-06-18' }); response.end(JSON.stringify(body.method ? { jsonrpc: '2.0', id: body.id, result: result.error ? undefined : result, error: result.error || undefined } : result)); return;
      } catch (error) { response.writeHead(502, { 'content-type': 'application/json' }); response.end(JSON.stringify({ error: 'TARGET_ERROR', message: error.message })); return; }
    }
    const result = await firewall.api(request.method, url.pathname, body, sessionId);
    const headers = { 'content-type': 'application/json' }; if (url.pathname === '/api/auth/login' && result.body?.session?.id) headers['set-cookie'] = `session=${encodeURIComponent(result.body.session.id)}; HttpOnly; SameSite=Lax; Path=/`;
    if (url.pathname === '/api/auth/logout' && result.status === 204) headers['set-cookie'] = 'session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/';
    response.writeHead(result.status, headers);
    response.end(result.status === 204 ? '' : JSON.stringify(result.body));
  });
}

export { DECISIONS, TRANSPORTS, APPROVAL_STATES, REDACTED };
