#!/usr/bin/env node
import { createServer } from '../mcp_server.mjs';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const server = createServer();
const transport = new StdioServerTransport();
await server.connect(transport);
