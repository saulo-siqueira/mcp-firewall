import http from 'node:http';

export function startMockMcpServer() {
  let calls = 0;
  const server = http.createServer((request, response) => {
    if (request.method !== 'POST') return response.writeHead(405).end();
    let body = ''; request.on('data', (chunk) => { body += chunk; }); request.on('end', () => { const message = JSON.parse(body); if (message.method === 'initialize') { response.setHeader('Mcp-Session-Id', 'mock-session'); response.setHeader('content-type', 'application/json'); return response.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { protocolVersion: '2025-06-18' } })); } if (message.method === 'notifications/initialized') return response.writeHead(202).end(); calls += 1; response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { content: [{ type: 'text', text: 'mock-ok' }] } })); });
  });
  return { server, get calls() { return calls; } };
}
