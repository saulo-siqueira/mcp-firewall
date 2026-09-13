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
      catch (error) { return { status: 404, body: { error: 'NOT_FOUND' } }; }
    }
    if (policyPath && method === 'DELETE') {
      if (!this.deletePolicy(decodeURIComponent(policyPath[1]))) return { status: 404, body: { error: 'NOT_FOUND' } };
      return { status: 204, body: null };
    }
    if (method === 'POST' && path === '/api/mcp-servers') {
      try { return { status: 201, body: this.addServer(body) }; }
      catch (error) { return { status: 422, body: { error: error.message } }; }
    }
    const approvalPath = path.match(/^\/api\/approvals\/([^/]+)\/(approve|reject)$/);
    if (approvalPath && method === 'POST') {
      const approvalId = decodeURIComponent(approvalPath[1]);
      if (approvalPath[2] === 'reject') {
        try { return { status: 200, body: this.reject(approvalId, body.approver || 'admin') }; }
        catch { return { status: 404, body: { error: 'NOT_FOUND' } }; }
      }
      return this.approve(approvalId, body.approver || 'admin')
        .then((result) => ({ status: 200, body: result }))
        .catch(() => ({ status: 409, body: { error: 'APPROVAL_NOT_PENDING' } }));
    }
    return { status: 404, body: { error: 'NOT_FOUND' } };
  }

  start({ headless = false } = {}) { return { headless, running: true, dashboard: headless ? null : 'http://localhost:3210' }; }
  startOutput() { return `MCP Firewall v${'0.1.0'}\n\nPolicies loaded: ${this.policies.size}\nMCP servers: ${this.servers.size}\n\nGateway running.\nDashboard: http://localhost:3210`; }

  dashboardHtml() { const allowed = [...this.audit.values()].filter((x) => x.decision === 'ALLOW').length; const blocked = [...this.audit.values()].filter((x) => x.decision === 'DENY').length; const approvals = [...this.audit.values()].filter((x) => x.decision === 'REQUIRE_APPROVAL').length; const recent = [...this.audit.values()].slice(-5).reverse().map((x) => `<article>${x.tool} · ${x.decision}</article>`).join('') || '<p class="empty">No tool calls recorded yet.</p>'; const active = [...this.policies.values()].filter((x) => x.enabled).map((x) => `<article>${x.name} · ${x.action}</article>`).join('') || '<p class="empty">No active policies.</p>'; const secrets = [...this.audit.values()].filter((x) => JSON.stringify(x.arguments).includes(REDACTED)).length; return shell('Dashboard', `<h1>Dashboard</h1><section class="metrics"><b>Total Tool Calls ${this.audit.size}</b><b>Allowed ${allowed}</b><b>Blocked ${blocked}</b><b>Requires Approval ${approvals}</b></section><section class="workspace-grid"><div><h2>Recent Calls</h2>${recent}</div><div><h2>Active Policies</h2>${active}</div><div><h2>Secrets Intercepted</h2><p>${secrets}</p></div></section>`); }
  auditDetailHtml(auditId) { const event = this.audit.get(auditId); return shell('Audit Logs', `<h1>Audit Logs</h1><pre>${escapeHtml(JSON.stringify(event, null, 2))}</pre>`); }
  approvalsHtml() { return shell('Approvals', `<h1>Approvals</h1>${[...this.approvals.values()].map((a) => `<article><strong>${a.status}</strong> ${a.tool}<button>Approve</button><button>Reject</button></article>`).join('') || '<p class="empty">No pending approvals.</p>'}`); }
  serversHtml() { return shell('MCP Servers', `<h1>MCP Servers</h1>${[...this.servers.values()].map((s) => `<article>${s.name}: <strong>${s.status}</strong></article>`).join('') || '<p class="empty">No MCP servers configured.</p>'}`); }
  loginHtmlLegacy() { return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Create Admin Account</title><style>body{margin:0;background:#fcfaf7;color:#423d38;font:14px ui-sans-serif,system-ui}.login{min-height:100vh;display:grid;grid-template-columns:1fr 1fr}.visual{padding:64px;background:#fff;display:grid;place-content:center}.panel{background:#ff6b00;padding:64px;display:grid;place-content:center}.card{background:#fff;border-radius:8px;padding:32px;min-width:280px}input{display:block;width:100%;margin:8px 0;padding:10px;border:1px solid #e3e0dd;border-radius:6px}button{background:#fe6e00;color:#fff;border:0;padding:10px 16px;border-radius:6px}@media(max-width:700px){.login{grid-template-columns:1fr}.visual{display:none}}</style></head><body><main class="login"><section class="visual"><h1>MCP Firewall</h1><p>Policy control between agents and tools.</p></section><section class="panel"><form class="card"><h2>Create Admin Account</h2><label>Name<input name="name"></label><label>Email<input name="email" type="email"></label><label>Password<input name="password" type="password"></label><label>Confirm Password<input name="confirmPassword" type="password"></label><button>Create Admin</button></form></section></main></body></html>`; }
  loginHtml() { return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>MCP Firewall Admin</title><style>body{margin:0;background:#fcfaf7;color:#423d38;font:14px ui-sans-serif,system-ui}.login{min-height:100vh;display:grid;grid-template-columns:1fr 1fr}.visual{padding:64px;background:#fff;display:grid;place-content:center}.panel{background:#ff6b00;padding:64px;display:grid;place-content:center}.card{background:#fff;border-radius:8px;padding:32px;min-width:280px}input{display:block;width:100%;margin:8px 0;padding:10px;border:1px solid #e3e0dd;border-radius:6px}button{background:#fe6e00;color:#fff;border:0;padding:10px 16px;border-radius:6px}@media(max-width:700px){.login{grid-template-columns:1fr}.visual{display:none}}</style></head><body><main class="login"><section class="visual"><h1>MCP Firewall</h1><p>Policy control between agents and tools.</p></section><section class="panel"><form class="card" id="admin-setup"><h2>Create Admin Account</h2><input name="name" placeholder="Name" required><input name="email" type="email" placeholder="Email" required><input name="password" type="password" placeholder="Password" required><input name="confirmPassword" type="password" placeholder="Confirm Password" required><button>Create Admin</button></form><form class="card" id="admin-login"><h2>Sign in</h2><input name="email" type="email" placeholder="Email" required><input name="password" type="password" placeholder="Password" required><button>Sign in</button></form></section></main><script>const submit=async(form,path)=>{form.addEventListener('submit',async(event)=>{event.preventDefault();const body=Object.fromEntries(new FormData(form));const response=await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const data=await response.json();if(!response.ok)return alert(data.error||'Request failed');if(data.session)localStorage.setItem('mcp-firewall-session',data.session.id);location.href='/api/dashboard';});};submit(document.querySelector('#admin-setup'),'/api/auth/setup');submit(document.querySelector('#admin-login'),'/api/auth/login');</script></body></html>`; }
  toolCallsHtml() { return shell('Tool Calls', `<h1>Tool Calls</h1>${[...this.audit.values()].map((event) => `<article><strong>${event.tool}</strong> · ${event.agent} · ${event.server} · ${event.decision}</article>`).join('') || '<p class="empty">No tool calls recorded yet.</p>'}`); }
  policiesHtml() { return shell('Policies', `<h1>Policies</h1>${[...this.policies.values()].map((policy) => `<article><strong>${policy.name}</strong> · ${policy.action} · ${policy.enabled ? 'Enabled' : 'Disabled'}</article>`).join('') || '<p class="empty">No policies configured.</p>'}<button>Create policy</button>`); }
  settingsHtml() { return shell('Settings', `<h1>Settings</h1><p>Gateway configuration and session settings.</p>`); }
  renderView(view = 'dashboard') {
    const views = { dashboard: () => this.dashboardHtml(), 'tool-calls': () => this.toolCallsHtml(), policies: () => this.policiesHtml(), 'mcp-servers': () => this.serversHtml(), approvals: () => this.approvalsHtml(), 'audit-logs': () => this.auditDetailHtml([...this.audit.keys()][0]), settings: () => this.settingsHtml(), login: () => this.loginHtml() };
    return (views[view] || views.dashboard)();
  }
}

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const shell = (active, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${active}</title><style>
  :root{font-family:ui-sans-serif,system-ui,sans-serif;color:#423d38;background:#fcfaf7}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#fcfaf7} .app{display:grid;grid-template-columns:256px 1fr;min-height:100vh}.shell-sidebar,.shell-header{background:rgba(0,0,0,.70);color:#fff;border-color:rgba(255,255,255,.1)}.shell-sidebar{padding:24px 16px}.brand{font-size:18px;font-weight:700;letter-spacing:-.02em;margin:0 0 32px}.nav{display:grid;gap:8px}.nav a{color:rgba(255,255,255,.7);text-decoration:none;padding:8px 12px;border-radius:8px;font-size:13px;font-weight:700}.nav a.active,.nav a:hover{background:#fe6e00;color:#fff}.main{min-width:0}.shell-header{height:64px;padding:0 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.1);backdrop-filter:blur(12px)}.shell-header small{color:rgba(255,255,255,.7)}.content{max-width:1400px;padding:32px;margin:0 auto}h1{font-size:24px;margin:0 0 24px}h2{font-size:18px;margin:0 0 16px}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:32px}.metrics b{background:#fff;border:1px solid #e3e0dd;border-radius:12px;padding:24px;display:grid;gap:8px;font-size:14px}.metrics b::first-line{font-size:20px}.workspace-grid{display:grid;grid-template-columns:2fr 1fr;gap:24px}.workspace-grid>div{background:#fff;border:1px solid #e3e0dd;border-radius:12px;padding:24px;min-height:150px}.workspace-grid>div:first-child{grid-row:span 2}.empty{color:#797067}article{background:#fff;border:1px solid #e3e0dd;border-radius:8px;padding:16px;margin:8px 0}button{background:#fe6e00;color:#fff;border:0;padding:8px 12px;margin:8px;border-radius:6px}pre{white-space:pre-wrap;background:#fff;padding:24px;border-radius:12px;border:1px solid #e3e0dd}@media(max-width:800px){.app{grid-template-columns:1fr}.shell-sidebar{padding:16px}.nav{display:flex;overflow:auto}.content{padding:24px 16px}.metrics,.workspace-grid{grid-template-columns:1fr}.workspace-grid>div:first-child{grid-row:auto}}
  </style></head><body><div class="app"><aside class="shell-sidebar"><p class="brand">MCP Firewall</p><nav class="nav">${['Dashboard','Tool Calls','Policies','MCP Servers','Approvals','Audit Logs','Settings'].map((item) => { const view = item.toLowerCase().replaceAll(' ', '-'); return `<a class="${item === active ? 'active' : ''}" href="/api/dashboard?view=${view}">${item}</a>`; }).join('')}</nav></aside><div class="main"><header class="shell-header"><strong>${active}</strong><small>ADMIN · LOCAL GATEWAY</small></header><main class="content"><div class="state" data-state="loading" hidden>Loading</div><div class="state error" data-state="error" hidden>Error loading data</div>${body}</main></div></div></body></html>`;
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
    if (request.method === 'GET' && url.pathname === '/api/dashboard') { response.writeHead(200, { 'content-type': 'text/html' }); response.end(firewall.renderView(url.searchParams.get('view') || 'dashboard')); return; }
    let body = {};
    try { if (request.method !== 'GET' && request.method !== 'HEAD') body = await readJsonBody(request); }
    catch { response.writeHead(400, { 'content-type': 'application/json' }); response.end(JSON.stringify({ error: 'INVALID_JSON' })); return; }
    const sessionId = request.headers['x-session-id'] || String(request.headers.authorization || '').replace(/^Bearer\s+/i, '') || undefined;
    const result = await firewall.api(request.method, url.pathname, body, sessionId);
    response.writeHead(result.status, { 'content-type': 'application/json' });
    response.end(result.status === 204 ? '' : JSON.stringify(result.body));
  });
}

export { DECISIONS, TRANSPORTS, APPROVAL_STATES, REDACTED };
