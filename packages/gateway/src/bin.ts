#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseGatewayYaml, loadGatewayConfig, startGatewayStandalone } from './index.js';

const args = process.argv.slice(2);
let configPath: string | undefined;
let portOverride: number | undefined;
let lockfileOverride: string | undefined;

for (let i = 0; i < args.length; i++) {
  if ((args[i] === '--config' || args[i] === '-c') && args[i + 1]) {
    configPath = args[++i];
  } else if ((args[i] === '--port' || args[i] === '-p') && args[i + 1]) {
    portOverride = Number(args[++i]);
  } else if (args[i] === '--lockfile' && args[i + 1]) {
    lockfileOverride = args[++i];
  } else if (args[i] === '--help' || args[i] === '-h') {
    console.log('Usage: toolveto-gateway [--config <path>] [--port <port>] [--lockfile <toolveto.lock.json>]');
    process.exit(0);
  }
}

const baseConfig = configPath
  ? parseGatewayYaml(fs.readFileSync(path.resolve(configPath), 'utf-8'))
  : loadGatewayConfig();

if (portOverride !== undefined && !Number.isNaN(portOverride)) {
  baseConfig.port = portOverride;
}
if (lockfileOverride) {
  baseConfig.lockfilePath = lockfileOverride;
}

startGatewayStandalone(baseConfig);
