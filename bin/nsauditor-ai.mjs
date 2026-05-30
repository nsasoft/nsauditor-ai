#!/usr/bin/env node
import { main } from '../cli.mjs';
main().catch((err) => { console.error(err?.stack || err); process.exit(1); });
