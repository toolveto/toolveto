#!/usr/bin/env node

import { createProgram } from '../src/index.js';

process.on('uncaughtException', (err) => {
  console.error(`[ToolVeto Fatal] Uncaught exception: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error(`[ToolVeto Fatal] Unhandled rejection: ${reason instanceof Error ? reason.message : String(reason)}`);
  process.exit(1);
});

const program = createProgram();
program.parse(process.argv);
