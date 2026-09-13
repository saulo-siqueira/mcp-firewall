# MCP Firewall

MCP Firewall is a local policy gateway between AI agents and MCP servers. It applies deterministic `ALLOW`, `DENY` and `REQUIRE_APPROVAL` decisions, redacts secrets before forwarding, and records every tool call.

## Quick start

```bash
npm install
npm test
node src/cli.js init
docker compose up --build
```

The same workflow is supported with pnpm: `pnpm install`, `pnpm dev`, and `pnpm test`. The development server is available at `http://localhost:3210`.

Open [http://localhost:3210/](http://localhost:3210/) for the React/Vite Command Center, or `/api/dashboard` for the server-rendered fallback. The Fastify MCP gateway supports `POST /mcp`, the SDK-backed Streamable HTTP endpoint `POST|GET|DELETE /mcp/sdk`, and the compatibility boundary `POST /mcp/tools/call`; administration is under `/api`.

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

## Architecture

The gateway receives an MCP tool call, evaluates YAML policies, redacts sensitive arguments, optionally pauses for an administrator, forwards to a configured STDIO or Streamable HTTP server, and records an audit event. The administrative Command Center uses the local `/api` HTTP boundary and does not participate in headless policy decisions.

## What and why

MCP Firewall is the policy boundary between an AI agent and MCP tools. A call without a matching allow policy starts BLOCKED, so a new installation fails closed until an administrator explicitly configures access. Every decision is auditable and secrets are redacted before forwarding.

## Dashboard and CLI

The Command Center provides Dashboard, Tool Calls, Policies, MCP Servers, Approvals, Audit Logs and Settings views. Use `mcp-firewall init` for the YAML contract, `mcp-firewall start` for the gateway and dashboard, or `mcp-firewall start --headless` for a STDIO-only gateway without human approvals.

## Configuration and security

Policy matches support `agent`, `server` and `tool`, including `*` wildcards. Decisions use `DENY > REQUIRE_APPROVAL > ALLOW`, with default deny. API keys, tokens, passwords, private keys and environment secrets are replaced with `[REDACTED]` before forwarding or persistence. The first-access flow creates the only MVP role, `ADMIN`; sessions are cookie-based, expire, and can be logged out.

## Development

Run `npm test` for the unit and boundary suite. Use `node src/server.js` to run the local server, `node src/cli.js init` to create the YAML file, and `node src/cli.js start --headless` for a core-only process. Docker Compose provides the Firewall/API and PostgreSQL services for local infrastructure.

## Roadmap

Future work may add SSO/OAuth/MFA, multi-tenant controls, observability exporters, and external approval providers. These are intentionally outside the MVP.

## Contributing

Open an issue with a reproducible MCP call, policy, expected decision, and audit result. Keep decisions deterministic and add a regression test for every behavior change.
