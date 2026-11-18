#!/usr/bin/env node
import {
  attachStdioTransport,
  IfayMcpServer,
  MCP_SERVER_NAME,
  MCP_SERVER_VERSION,
} from './index.js';

const args = process.argv.slice(2);

if (args.includes('--version') || args.includes('-v')) {
  process.stdout.write(`${MCP_SERVER_NAME}@${MCP_SERVER_VERSION}\n`);
  process.exit(0);
}

if (args.includes('--help') || args.includes('-h')) {
  process.stdout.write(
    [
      `${MCP_SERVER_NAME} v${MCP_SERVER_VERSION}`,
      '',
      'Zero-dependency Model Context Protocol (MCP) stdio server for iFay.',
      '',
      'Usage:',
      '  ifay-mcp-server              Start newline-delimited JSON-RPC 2.0 MCP server on stdio',
      '  ifay-mcp-server --version    Print server version',
      '  ifay-mcp-server --help       Show this help message',
      '',
      'Exposed MCP Tools:',
      '  - fayid_validate             Validate canonical FayID format, DID, & Ed25519 key binding',
      '  - faymanifest_validate       Validate FayManifest JSON against faymanifest.schema.json',
      '  - cap_evaluate               Evaluate AI agent Host/tool actions against CAP 1.0 + Mandate',
      '  - ssp_verify_descriptor      Verify SSP 1.0 SkillDescriptor & Detached Ed25519 JWS proof',
      '',
    ].join('\n'),
  );
  process.exit(0);
}

const server = new IfayMcpServer();
attachStdioTransport(server, process.stdin, process.stdout);
