import { describe, expect, it } from 'vitest';
import { startMockMcpServer } from '../fixtures/mock-mcp-server';

describe('Firewall to Mock MCP Server integration', () => {
  it('provides an independent MCP target fixture', () => { const target = startMockMcpServer(); expect(typeof target.server.listen).toBe('function'); target.server.close(); });
});
