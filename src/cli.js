#!/usr/bin/env node
import { access, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { Firewall, loadConfigFile } from './index.js';

export async function init(directory = process.cwd()) {
  const file = join(directory, 'mcp-firewall.yaml');
  try { await access(file, constants.F_OK); throw new Error('mcp-firewall.yaml already exists'); }
  catch (error) { if (error.message.includes('already exists')) throw error; }
  await writeFile(file, 'version: 1\npolicies: []\nmcp_servers: []\n');
  return file;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [command, flag, extra] = process.argv.slice(2);
  try {
    if (command === 'init') { await init(); console.log('Created mcp-firewall.yaml'); }
    else if (command === 'start') {
      const firewall = existsSync(join(process.cwd(), 'mcp-firewall.yaml')) ? loadConfigFile(join(process.cwd(), 'mcp-firewall.yaml'), { storagePath: join(process.cwd(), '.mcp-firewall-data.json') }) : new Firewall({ storagePath: join(process.cwd(), '.mcp-firewall-data.json') });
      const output = firewall.startOutput();
      console.log(flag === '--headless' ? output.replace('\nDashboard: http://localhost:3210', '\nHeadless mode: enabled') : output);
      if (extra !== '--check') {
        const { createApiServer, startStdioGateway } = await import('./index.js');
        const port = Number(process.env.PORT || 3210);
        createApiServer(firewall).listen(port, '0.0.0.0', () => console.log(`Gateway listening on port ${port}`));
        if (flag === '--headless') startStdioGateway(firewall);
      }
    }
    else { console.error('Usage: mcp-firewall init | start [--headless]'); process.exitCode = 1; }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
