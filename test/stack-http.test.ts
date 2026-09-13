import { expect, test } from 'vitest';
import { app, firewall } from '../src/server.ts';

test('Fastify exposes the production MCP compatibility boundary', async () => { firewall.policies.clear(); firewall.servers.clear(); firewall.addPolicy({ name: 'allow-test', match: { tool: 'test.echo' }, action: 'allow', enabled: true }); firewall.addServer({ name: 'mock', transport: 'stdio', command: process.execPath, args: ['-e', "process.stdin.on('data',()=>process.stdout.write(JSON.stringify({ok:true})))"] }); const response = await app.inject({ method: 'POST', url: '/mcp/tools/call', payload: { agent: 'test', server: 'mock', tool: 'test.echo', arguments: {} } }); expect(response.statusCode).toBe(200); expect(response.json().decision).toBe('ALLOW'); await app.close(); });
