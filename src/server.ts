import Fastify from 'fastify';
import { z } from 'zod';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import fastifyStatic from '@fastify/static';
import { Firewall, handleMcpMessage, loadConfigFile } from './index.js';
import { createDatabase } from './db/client.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

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
const app = Fastify({ logger: { level: process.env.LOG_LEVEL || 'info' } });
const callSchema = z.object({ agent: z.string().optional(), server: z.string().optional(), tool: z.string().optional(), arguments: z.record(z.string(), z.unknown()).optional(), method: z.string().optional(), params: z.record(z.string(), z.unknown()).optional() });
if (existsSync(join(root, 'dist'))) await app.register(fastifyStatic, { root: join(root, 'dist'), wildcard: true });
app.get('/', async (_request, reply) => reply.sendFile('index.html'));

app.get('/health', async () => ({ status: 'ok', database: Boolean(database), mcp: Boolean(mcpServer) }));
app.post('/mcp', async (request, reply) => { const parsed = callSchema.safeParse(request.body); if (!parsed.success) return reply.code(400).send({ error: 'INVALID_MCP_REQUEST', details: parsed.error.flatten() }); const body: any = parsed.data; const result = body.method ? await handleMcpMessage(firewall, body, { agent: request.headers['mcp-agent'], server: request.headers['mcp-server'] }) : await firewall.handleCall(body); return reply.header('MCP-Protocol-Version', '2025-06-18').send(body.method ? { jsonrpc: '2.0', id: body.id, result: result.error ? undefined : result, error: result.error || undefined } : result); });
const sessionFrom = (request: any) => request.headers['x-session-id'] || String(request.headers.authorization || '').replace(/^Bearer\s+/i, '') || String(request.headers.cookie || '').split(';').map((x: string) => x.trim()).find((x: string) => x.startsWith('session='))?.slice(8);
app.get('/api/dashboard', async (request, reply) => { const session = sessionFrom(request); const view = (request.query as any)?.view || 'dashboard'; if (view !== 'login' && firewall.users.size && !firewall.authorize(session)) return reply.code(401).send({ error: 'UNAUTHORIZED', login: '/api/dashboard?view=login' }); return reply.type('text/html').send(view === 'login' || !firewall.users.size ? firewall.loginHtml() : firewall.renderView(view)); });
const adminApi = async (request: any, reply: any) => {
  const result = await firewall.api(request.method, request.url.split('?')[0], request.body || {}, sessionFrom(request));
  if (result.status === 204) return reply.code(204).send();
  if (result.body?.session?.id && request.url.startsWith('/api/auth/login')) reply.header('set-cookie', `session=${encodeURIComponent(result.body.session.id)}; HttpOnly; SameSite=Lax; Path=/`);
  if (request.url.startsWith('/api/auth/logout') && result.status === 204) reply.header('set-cookie', 'session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/');
  return reply.code(result.status).send(result.body);
};
app.all('/api/*', adminApi);

const port = Number(process.env.PORT || 3210);
if (process.env.NODE_ENV !== 'test') app.listen({ port, host: '0.0.0.0' }).catch((error) => { app.log.error(error); process.exit(1); });
export { app, firewall };
