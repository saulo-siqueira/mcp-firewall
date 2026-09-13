import Fastify from 'fastify';
import { z } from 'zod';
import { existsSync } from 'node:fs';
import crypto from 'node:crypto';
import { join } from 'node:path';
import fastifyStatic from '@fastify/static';
import { Firewall, handleMcpMessage, loadConfigFile } from './index.js';
import { createDatabase } from './db/client.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { appendAudit, ensureDatabase, loadConfiguration, syncConfiguration } from './db/repository.js';

const root = process.cwd();
const configPath = join(root, 'mcp-firewall.yaml');
const firewall = existsSync(configPath) ? loadConfigFile(configPath, { storagePath: process.env.STORAGE_PATH || join(root, '.mcp-firewall-data.json') }) : new Firewall({ storagePath: process.env.STORAGE_PATH || join(root, '.mcp-firewall-data.json') });
const database = createDatabase();
const mcpServer = new Server({ name: 'mcp-firewall', version: '0.1.0' }, { capabilities: { tools: {} } });
// Keep the SDK request handlers as the canonical MCP contract for transports added later.
mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
  const params: any = request.params;
  const result = await firewall.handleCall({ agent: process.env.MCP_AGENT || 'mcp-client', server: process.env.MCP_SERVER, tool: params.name, arguments: params.arguments || {} });
  if (result.error) throw new Error(result.error.message);
  return { content: [{ type: 'text', text: JSON.stringify(result.result ?? null) }] };
});
const transports = new Map<string, { transport: StreamableHTTPServerTransport; server: Server }>();
const createSdkServer = () => { const server = new Server({ name: 'mcp-firewall', version: '0.1.0' }, { capabilities: { tools: {} } }); server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] })); server.setRequestHandler(CallToolRequestSchema, async (request: any) => { const result = await firewall.handleCall({ agent: process.env.MCP_AGENT || 'mcp-client', server: process.env.MCP_SERVER, tool: request.params.name, arguments: request.params.arguments || {} }); if (result.error) throw new Error(result.error.message); return { content: [{ type: 'text', text: JSON.stringify(result.result ?? null) }] }; }); return server; };
const app = Fastify({ logger: { level: process.env.LOG_LEVEL || 'info' } });
const callSchema = z.object({ agent: z.string().optional(), server: z.string().optional(), tool: z.string().optional(), arguments: z.record(z.string(), z.unknown()).optional(), method: z.string().optional(), params: z.record(z.string(), z.unknown()).optional() });
if (existsSync(join(root, 'dist'))) await app.register(fastifyStatic, { root: join(root, 'dist'), wildcard: true });
app.get('/', async (_request, reply) => reply.sendFile('index.html'));

app.get('/health', async () => ({ status: 'ok', database: Boolean(database), mcp: Boolean(mcpServer) }));
app.post('/mcp', async (request, reply) => { const parsed = callSchema.safeParse(request.body); if (!parsed.success) return reply.code(400).send({ error: 'INVALID_MCP_REQUEST', details: parsed.error.flatten() }); const body: any = parsed.data; const result = body.method ? await handleMcpMessage(firewall, body, { agent: request.headers['mcp-agent'], server: request.headers['mcp-server'] }) : await firewall.handleCall(body); if (database && result?.audit) { try { await appendAudit(database, result.audit); } catch (error) { request.log.error({ error }, 'postgres audit synchronization failed'); } } return reply.header('MCP-Protocol-Version', '2025-06-18').send(body.method ? { jsonrpc: '2.0', id: body.id, result: result.error ? undefined : result, error: result.error || undefined } : result); });
app.all('/mcp/sdk', async (request, reply) => { const requested = request.headers['mcp-session-id'] as string | undefined; const isInitialize = request.method === 'POST' && (request.body as any)?.method === 'initialize'; let connection = requested ? transports.get(requested) : undefined; if (!connection && !isInitialize) return reply.code(400).send({ error: 'MCP_SESSION_REQUIRED' }); if (!connection) { const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => crypto.randomUUID() }); const server = createSdkServer(); await server.connect(transport); connection = { transport, server }; transport.onclose = () => { if (transport.sessionId) transports.delete(transport.sessionId); }; } reply.hijack(); await connection.transport.handleRequest(request.raw, reply.raw, request.method === 'GET' ? undefined : request.body); if (connection.transport.sessionId) transports.set(connection.transport.sessionId, connection); if (request.method === 'DELETE') { transports.delete(requested || ''); await connection.transport.close(); } });
const sessionFrom = (request: any) => request.headers['x-session-id'] || String(request.headers.authorization || '').replace(/^Bearer\s+/i, '') || String(request.headers.cookie || '').split(';').map((x: string) => x.trim()).find((x: string) => x.startsWith('session='))?.slice(8);
app.get('/api/dashboard', async (request, reply) => { const session = sessionFrom(request); const view = (request.query as any)?.view || 'dashboard'; if (view !== 'login' && firewall.users.size && !firewall.authorize(session)) return reply.code(401).send({ error: 'UNAUTHORIZED', login: '/api/dashboard?view=login' }); return reply.type('text/html').send(view === 'login' || !firewall.users.size ? firewall.loginHtml() : firewall.renderView(view)); });
const adminApi = async (request: any, reply: any) => {
  const result = await firewall.api(request.method, request.url.split('?')[0], request.body || {}, sessionFrom(request));
  if (database && result.status < 400) { try { await syncConfiguration(database, firewall); for (const event of firewall.audit.values()) await appendAudit(database, event); } catch (error) { request.log.error({ error }, 'postgres synchronization failed'); } }
  if (result.status === 204) return reply.code(204).send();
  if (result.body?.session?.id && request.url.startsWith('/api/auth/login')) reply.header('set-cookie', `session=${encodeURIComponent(result.body.session.id)}; HttpOnly; SameSite=Lax; Path=/`);
  if (request.url.startsWith('/api/auth/logout') && result.status === 204) reply.header('set-cookie', 'session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/');
  return reply.code(result.status).send(result.body);
};
app.all('/api/*', adminApi);

const port = Number(process.env.PORT || 3210);
if (process.env.NODE_ENV !== 'test') {
  if (database) { try { await ensureDatabase(database); const stored = await loadConfiguration(database); if (stored.policies.length && !firewall.policies.size) stored.policies.forEach((policy: any) => firewall.addPolicy(policy)); if (stored.servers.length && !firewall.servers.size) stored.servers.forEach((server: any) => firewall.addServer(server)); if (stored.users.length || stored.sessions.length || stored.approvals.length) firewall.restore(stored as any); } catch (error) { app.log.error({ error }, 'postgres initialization failed'); } }
  app.listen({ port, host: '0.0.0.0' }).catch((error) => { app.log.error(error); process.exit(1); });
}
export { app, firewall };
