#!/usr/bin/env node
import { access, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { Firewall } from './index.js';

export async function init(directory = process.cwd()) {
  const file = join(directory, 'mcp-firewall.yaml');
  try { await access(file, constants.F_OK); throw new Error('mcp-firewall.yaml already exists'); }
  catch (error) { if (error.message.includes('already exists')) throw error; }
  await writeFile(file, 'version: 1\npolicies: []\nmcp_servers: []\n');
  return file;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [command, flag] = process.argv.slice(2);
  try {
    if (command === 'init') { await init(); console.log('Created mcp-firewall.yaml'); }
    else if (command === 'start') {
      const output = new Firewall().startOutput();
      console.log(flag === '--headless' ? output.replace('\nDashboard: http://localhost:3210', '\nHeadless mode: enabled') : output);
    }
    else { console.error('Usage: mcp-firewall init | start [--headless]'); process.exitCode = 1; }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
