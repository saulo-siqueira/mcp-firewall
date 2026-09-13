import crypto from 'node:crypto';
import http from 'node:http';

const DECISIONS = ['ALLOW', 'DENY', 'REQUIRE_APPROVAL'];
const TRANSPORTS = ['stdio', 'http'];
const APPROVAL_STATES = ['PENDING', 'APPROVED', 'REJECTED'];
const REDACTED = '[REDACTED]';

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
const redact = (value) => {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, secretKey(key) ? REDACTED : redact(item)]));
};

const id = (prefix) => `${prefix}_${crypto.randomUUID()}`;
const now = () => new Date().toISOString();

export class Firewall {
  constructor({ policies = [], servers = [], approvalAvailable = true } = {}) {
    this.policies = new Map(); this.servers = new Map(); this.users = new Map(); this.sessions = new Map();
    this.approvals = new Map(); this.audit = new Map(); this.approvalAvailable = approvalAvailable;
    policies.forEach((policy) => this.addPolicy(policy));
    servers.forEach((server) => this.addServer(server));
  }

  addPolicy(input) {
    const name = input?.name || id('policy');
    if (this.policies.has(name)) { const error = new Error('policy already exists'); error.code = 'CONFLICT'; throw error; }
    if (!DECISIONS.includes(input.action.toUpperCase())) throw new Error('invalid policy action');
    const policy = { enabled: true, ...input, name, action: input.action.toUpperCase() };
    this.policies.set(policy.name, policy); return policy;
  }

  updatePolicy(name, changes) { const current = this.policies.get(name); if (!current) throw new Error('policy not found'); const next = { ...current, ...changes }; this.policies.set(name, next); return next; }
  getPolicy(name) { return this.policies.get(name); }
  deletePolicy(name) { return this.policies.delete(name); }
  policyYaml(name) { const p = this.getPolicy(name); if (!p) throw new Error('policy not found'); return `version: 1\npolicies:\n  - name: ${p.name}\n    match:\n      tool: ${p.match?.tool || '*'}\n    action: ${p.action.toLowerCase()}\n    enabled: ${p.enabled}\n`; }

  addServer(input) {
    const transport = input?.transport || 'stdio';
    if (!input?.name || !TRANSPORTS.includes(transport)) throw new Error('transport must be stdio or http');
    const server = { status: input.status || 'Disconnected', transport, ...input };
    this.servers.set(server.name, server); return server;
  }

  evaluate(input) {
    const call = createMcpCall(input); const candidates = [...this.policies.values()].filter((p) => p.enabled && policyMatches(p, call));
    const rank = { ALLOW: 1, REQUIRE_APPROVAL: 2, DENY: 3 };
    candidates.sort((a, b) => rank[b.action] - rank[a.action]);
    const policy = candidates[0]; return { decision: policy?.action || 'DENY', policy: policy?.name || null, call };
  }

  async handleCall(input) {
    const evaluated = this.evaluate(input); const call = { ...evaluated.call, arguments: redact(evaluated.call.arguments) };
    const started = Date.now(); const base = { id: id('audit'), agent: call.agent, server: call.server, tool: call.tool, arguments: call.arguments, decision: evaluated.decision, policy: evaluated.policy, duration: 0, result: null, created_at: now() };
    const finish = (result, error = null) => { base.duration = Date.now() - started; base.result = result ?? error?.message ?? null; this.audit.set(base.id, base); return { ...result && typeof result === 'object' ? result : {}, decision: evaluated.decision, result, error, audit: base }; };
    if (evaluated.decision === 'DENY') return finish(null, { code: 'POLICY_DENIED', message: 'MCP call denied by policy' });
    if (evaluated.decision === 'REQUIRE_APPROVAL' && !input._approved) {
      if (!this.approvalAvailable) { const unavailable = finish(null, { code: 'APPROVAL_UNAVAILABLE', message: 'approval mechanism unavailable' }); unavailable.decision = 'DENY'; return unavailable; }
      const approval = { id: id('approval'), status: 'PENDING', agent: call.agent, server: call.server, tool: call.tool, arguments: call.arguments, requested_at: now(), policy: evaluated.policy, call };
      this.approvals.set(approval.id, approval); return finish(null, null) && { decision: 'REQUIRE_APPROVAL', approval, audit: base };
    }
    const server = this.servers.get(call.server); let result;
    try { result = server?.handler ? await server.handler(call) : { ok: true, transport: server?.transport || 'stdio' }; return finish(result); }
    catch (error) { return finish(null, { code: 'TARGET_ERROR', message: error.message }); }
  }

  async approve(approvalId, approver) {
    const approval = this.approvals.get(approvalId); if (!approval || approval.status !== 'PENDING') throw new Error('approval is not pending');
    approval.status = 'APPROVED'; approval.approved_by = approver; approval.approved_at = now();
    const result = await this.handleCall({ ...approval.call, _approved: true });
    const audit = [...this.audit.values()].at(-1); if (audit) { audit.approved_by = approver; audit.approved_at = approval.approved_at; }
    return { ...result, approval };
  }

  reject(approvalId, rejecter) { const approval = this.approvals.get(approvalId); if (!approval || approval.status !== 'PENDING') throw new Error('approval is not pending'); approval.status = 'REJECTED'; approval.rejected_by = rejecter; approval.rejected_at = now(); return { decision: 'DENY', approval }; }

  setupAdmin({ name, email, password, confirmPassword }) {
    if (this.users.size) { const error = new Error('admin already exists'); error.code = 'CONFLICT'; throw error; }
    if (!name || !email || !password || password !== confirmPassword) throw new Error('invalid admin data');
    const user = { id: id('user'), name, email, password_hash: crypto.scryptSync(password, 'mcp-firewall', 32).toString('hex'), role: 'ADMIN', created_at: now(), updated_at: now() };
    this.users.set(email, user); return { ...user };
  }

  login(email, password) {
    const user = this.users.get(email); const hash = user && crypto.scryptSync(password, 'mcp-firewall', 32).toString('hex');
    if (!user || hash !== user.password_hash) throw new Error('invalid credentials');
    const session = { id: id('session'), userId: user.id, expires_at: Date.now() + 8 * 60 * 60 * 1000 }; this.sessions.set(session.id, session); return { user: { ...user, password_hash: undefined }, session };
  }

  authorize(sessionId) { const session = this.sessions.get(sessionId); if (!session || session.expires_at <= Date.now()) { this.sessions.delete(sessionId); return false; } return true; }
  logout(sessionId) { this.sessions.delete(sessionId); }

  start({ headless = false } = {}) { return { headless, running: true, dashboard: headless ? null : 'http://localhost:3210' }; }
  startOutput() { return `MCP Firewall v${'0.1.0'}\n\nPolicies loaded: ${this.policies.size}\nMCP servers: ${this.servers.size}\n\nGateway running.\nDashboard: http://localhost:3210`; }

  dashboardHtml() { const allowed = [...this.audit.values()].filter((x) => x.decision === 'ALLOW').length; const blocked = [...this.audit.values()].filter((x) => x.decision === 'DENY').length; const approvals = [...this.audit.values()].filter((x) => x.decision === 'REQUIRE_APPROVAL').length; return shell('Dashboard', `<h1>Dashboard</h1><section class="metrics"><b>Total Tool Calls ${this.audit.size}</b><b>Allowed ${allowed}</b><b>Blocked ${blocked}</b><b>Requires Approval ${approvals}</b></section><section class="workspace-grid"><div><h2>Recent Calls</h2><p class="empty">No tool calls recorded yet.</p></div><div><h2>Active Policies</h2><p class="empty">No active policies.</p></div><div><h2>Secrets Intercepted</h2><p class="empty">No secrets intercepted.</p></div></section>`); }
  auditDetailHtml(auditId) { const event = this.audit.get(auditId); return shell('Audit Logs', `<h1>Audit Logs</h1><pre>${escapeHtml(JSON.stringify(event, null, 2))}</pre>`); }
  approvalsHtml() { return shell('Approvals', `<h1>Approvals</h1>${[...this.approvals.values()].map((a) => `<article><strong>${a.status}</strong> ${a.tool}<button>Approve</button><button>Reject</button></article>`).join('') || '<p class="empty">No pending approvals.</p>'}`); }
  serversHtml() { return shell('MCP Servers', `<h1>MCP Servers</h1>${[...this.servers.values()].map((s) => `<article>${s.name}: <strong>${s.status}</strong></article>`).join('') || '<p class="empty">No MCP servers configured.</p>'}`); }
}

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const shell = (active, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${active}</title><style>
  :root{font-family:ui-sans-serif,system-ui,sans-serif;color:#423d38;background:#fcfaf7}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#fcfaf7} .app{display:grid;grid-template-columns:256px 1fr;min-height:100vh}.shell-sidebar,.shell-header{background:rgba(0,0,0,.70);color:#fff;border-color:rgba(255,255,255,.1)}.shell-sidebar{padding:24px 16px}.brand{font-size:18px;font-weight:700;letter-spacing:-.02em;margin:0 0 32px}.nav{display:grid;gap:8px}.nav a{color:rgba(255,255,255,.7);text-decoration:none;padding:8px 12px;border-radius:8px;font-size:13px;font-weight:700}.nav a.active,.nav a:hover{background:#fe6e00;color:#fff}.main{min-width:0}.shell-header{height:64px;padding:0 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.1);backdrop-filter:blur(12px)}.shell-header small{color:rgba(255,255,255,.7)}.content{max-width:1400px;padding:32px;margin:0 auto}h1{font-size:24px;margin:0 0 24px}h2{font-size:18px;margin:0 0 16px}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:32px}.metrics b{background:#fff;border:1px solid #e3e0dd;border-radius:12px;padding:24px;display:grid;gap:8px;font-size:14px}.metrics b::first-line{font-size:20px}.workspace-grid{display:grid;grid-template-columns:2fr 1fr;gap:24px}.workspace-grid>div{background:#fff;border:1px solid #e3e0dd;border-radius:12px;padding:24px;min-height:150px}.workspace-grid>div:first-child{grid-row:span 2}.empty{color:#797067}article{background:#fff;border:1px solid #e3e0dd;border-radius:8px;padding:16px;margin:8px 0}button{background:#fe6e00;color:#fff;border:0;padding:8px 12px;margin:8px;border-radius:6px}pre{white-space:pre-wrap;background:#fff;padding:24px;border-radius:12px;border:1px solid #e3e0dd}@media(max-width:800px){.app{grid-template-columns:1fr}.shell-sidebar{padding:16px}.nav{display:flex;overflow:auto}.content{padding:24px 16px}.metrics,.workspace-grid{grid-template-columns:1fr}.workspace-grid>div:first-child{grid-row:auto}}
  </style></head><body><div class="app"><aside class="shell-sidebar"><p class="brand">MCP Firewall</p><nav class="nav">${['Dashboard','Tool Calls','Policies','MCP Servers','Approvals','Audit Logs','Settings'].map((item) => `<a class="${item === active ? 'active' : ''}" href="#${item.toLowerCase().replaceAll(' ', '-')}">${item}</a>`).join('')}</nav></aside><div class="main"><header class="shell-header"><strong>${active}</strong><small>ADMIN · LOCAL GATEWAY</small></header><main class="content">${body}</main></div></div></body></html>`;
const page = (title, body) => shell(title, body);

export function createApiServer(firewall, { port = 3210 } = {}) {
  return http.createServer(async (request, response) => {
    if (request.method === 'GET' && request.url === '/api/dashboard') { response.writeHead(200, { 'content-type': 'text/html' }); response.end(firewall.dashboardHtml()); return; }
    if (request.method === 'GET' && request.url === '/api/approvals') { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify([...firewall.approvals.values()])); return; }
    response.writeHead(404, { 'content-type': 'application/json' }); response.end(JSON.stringify({ error: 'NOT_FOUND' }));
  });
}

export { DECISIONS, TRANSPORTS, APPROVAL_STATES, REDACTED };
