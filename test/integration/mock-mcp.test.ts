import { describe, expect, it } from 'vitest';
import { startMockMcpServer } from '../fixtures/mock-mcp-server';
import { Firewall } from '../../src/index.js';

describe('Firewall to Mock MCP Server integration', () => {
  it('forwards an allowed call to the independent target', async () => { const target = startMockMcpServer(); await new Promise<void>((resolve) => target.server.listen(0, '127.0.0.1', () => resolve())); const address = target.server.address() as { port: number }; const firewall = new Firewall({ servers: [{ name: 'mock', transport: 'http', url: `http://127.0.0.1:${address.port}` }], policies: [{ match: { tool: 'mock.echo' }, action: 'allow', enabled: true }] }); const result = await firewall.handleCall({ agent: 'test', server: 'mock', tool: 'mock.echo', arguments: { value: 'ok' } }); expect(result.decision).toBe('ALLOW'); expect(target.calls).toBe(1); target.server.close(); });
});
