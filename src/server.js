import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { createApiServer, Firewall, loadConfigFile } from './index.js';

const root = process.cwd();
const configPath = join(root, 'mcp-firewall.yaml');
const storagePath = join(root, '.mcp-firewall-data.json');
const firewall = existsSync(configPath) ? loadConfigFile(configPath, { storagePath }) : new Firewall({ storagePath });
const port = Number(process.env.PORT || 3210);
createApiServer(firewall, { port }).listen(port, '0.0.0.0', () => console.log(`MCP Firewall dashboard running at http://localhost:${port}/api/dashboard`));
