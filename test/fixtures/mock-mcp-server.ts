import http from 'node:http';

export function startMockMcpServer() {
  let calls = 0;
  const server = http.createServer((request, response) => {
    if (request.method !== 'POST') return response.writeHead(405).end();
    let body = ''; request.on('data', (chunk) => { body += chunk; }); request.on('end', () => { calls += 1; const message = JSON.parse(body); response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { content: [{ type: 'text', text: 'mock-ok' }] } })); });
  });
  return { server, get calls() { return calls; } };
}
