# MCP Firewall

MCP Firewall is a local policy gateway between AI agents and MCP servers. It applies deterministic `ALLOW`, `DENY` and `REQUIRE_APPROVAL` decisions, redacts secrets before forwarding, and records every tool call.

## Quick start

```bash
npm install
npm test
node src/cli.js init
docker compose up --build
```

Open [http://localhost:3210/api/dashboard](http://localhost:3210/api/dashboard) for the Command Center. The MCP gateway boundary is `POST /mcp/tools/call`; administration is under `/api`.

## Policy example

```yaml
version: 1
policies:
  - name: allow-read-files
    match:
      tool: filesystem.read
    action: allow
    enabled: true
  - name: block-destructive-actions
    match:
      tool: postgres.*
    action: deny
    enabled: true
```

The core can run without the dashboard with `node src/cli.js start --headless` or `mcp-firewall start --headless` after installation.
