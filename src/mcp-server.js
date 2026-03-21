#!/usr/bin/env node

/**
 * dev-crypto-toolkit MCP Server
 * Exposes all crypto utility tools via the Model Context Protocol (stdio transport).
 */

const readline = require('readline');
const tools = require('./tools');

// ─── Tool Definitions ────────────────────────────────────────────────────────

const TOOLS = [
  {
    name: 'jwt_decode',
    description: 'Decode a JWT token without verification. Returns header, payload, and timing info.',
    inputSchema: {
      type: 'object',
      properties: {
        token: { type: 'string', description: 'The JWT token string to decode' },
      },
      required: ['token'],
    },
  },
  {
    name: 'hash',
    description: 'Hash a string using MD5, SHA1, SHA256, or SHA512.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Text to hash' },
        algorithm: { type: 'string', enum: ['md5', 'sha1', 'sha256', 'sha512'], default: 'sha256' },
      },
      required: ['text'],
    },
  },
  {
    name: 'hmac',
    description: 'Generate HMAC for a string with a secret key.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Text to hash' },
        key: { type: 'string', description: 'Secret key' },
        algorithm: { type: 'string', enum: ['md5', 'sha1', 'sha256', 'sha512'], default: 'sha256' },
      },
      required: ['text', 'key'],
    },
  },
  {
    name: 'base64_encode',
    description: 'Encode text to Base64.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string', description: 'Text to encode' } },
      required: ['text'],
    },
  },
  {
    name: 'base64_decode',
    description: 'Decode Base64 string.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string', description: 'Base64 string to decode' } },
      required: ['text'],
    },
  },
  {
    name: 'url_encode',
    description: 'URL-encode a string.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string', description: 'Text to encode' } },
      required: ['text'],
    },
  },
  {
    name: 'url_decode',
    description: 'URL-decode a string.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string', description: 'URL-encoded string to decode' } },
      required: ['text'],
    },
  },
  {
    name: 'generate_uuid',
    description: 'Generate one or more UUID v4 values.',
    inputSchema: {
      type: 'object',
      properties: {
        count: { type: 'number', description: 'Number of UUIDs to generate (1-1000)', default: 1 },
      },
    },
  },
  {
    name: 'generate_password',
    description: 'Generate random passwords with configurable length and complexity.',
    inputSchema: {
      type: 'object',
      properties: {
        length: { type: 'number', description: 'Password length (4-256)', default: 16 },
        count: { type: 'number', description: 'Number of passwords', default: 1 },
        lowercase: { type: 'boolean', default: true },
        uppercase: { type: 'boolean', default: true },
        digits: { type: 'boolean', default: true },
        symbols: { type: 'boolean', default: true },
      },
    },
  },
  {
    name: 'random_bytes',
    description: 'Generate cryptographically secure random bytes.',
    inputSchema: {
      type: 'object',
      properties: {
        bytes: { type: 'number', description: 'Number of bytes (1-1024)', default: 32 },
        format: { type: 'string', enum: ['hex', 'base64', 'array'], default: 'hex' },
      },
    },
  },
  {
    name: 'password_hash',
    description: 'Hash a password using PBKDF2-SHA512 (bcrypt-style).',
    inputSchema: {
      type: 'object',
      properties: {
        password: { type: 'string', description: 'Password to hash' },
        iterations: { type: 'number', default: 100000 },
      },
      required: ['password'],
    },
  },
  {
    name: 'password_verify',
    description: 'Verify a password against a PBKDF2 hash.',
    inputSchema: {
      type: 'object',
      properties: {
        password: { type: 'string', description: 'Password to verify' },
        hash: { type: 'string', description: 'Hash string to verify against' },
      },
      required: ['password', 'hash'],
    },
  },
  {
    name: 'timestamp_convert',
    description: 'Convert between Unix timestamp, ISO 8601, and human-readable formats.',
    inputSchema: {
      type: 'object',
      properties: {
        timestamp: { description: 'Unix timestamp (seconds or ms), ISO string, or date string' },
      },
      required: ['timestamp'],
    },
  },
  {
    name: 'rot13',
    description: 'Apply ROT13 encoding/decoding to text.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string', description: 'Text to encode/decode' } },
      required: ['text'],
    },
  },
  {
    name: 'caesar_cipher',
    description: 'Apply Caesar cipher with configurable shift.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Text to encode' },
        shift: { type: 'number', description: 'Shift value (default: 3)', default: 3 },
      },
      required: ['text'],
    },
  },
];

// ─── Tool Execution ──────────────────────────────────────────────────────────

function executeTool(name, args) {
  switch (name) {
    case 'jwt_decode':       return tools.jwtDecode(args.token);
    case 'hash':             return tools.hash(args.text, args.algorithm);
    case 'hmac':             return tools.hmac(args.text, args.key, args.algorithm);
    case 'base64_encode':    return tools.base64Encode(args.text);
    case 'base64_decode':    return tools.base64Decode(args.text);
    case 'url_encode':       return tools.urlEncode(args.text);
    case 'url_decode':       return tools.urlDecode(args.text);
    case 'generate_uuid':    return tools.generateUUIDs(args.count);
    case 'generate_password': return tools.generatePasswords(args.length, args.count, args);
    case 'random_bytes':     return tools.randomBytes(args.bytes, args.format);
    case 'password_hash':    return tools.passwordHash(args.password, args.iterations);
    case 'password_verify':  return tools.passwordVerify(args.password, args.hash);
    case 'timestamp_convert': return tools.timestampConvert(args.timestamp);
    case 'rot13':            return tools.rot13(args.text);
    case 'caesar_cipher':    return tools.caesarCipher(args.text, args.shift);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ─── JSON-RPC MCP Server (stdio) ─────────────────────────────────────────────

const rl = readline.createInterface({ input: process.stdin, terminal: false });

let buffer = '';

function sendResponse(response) {
  const json = JSON.stringify(response);
  process.stdout.write(`Content-Length: ${Buffer.byteLength(json)}\r\n\r\n${json}`);
}

function handleMessage(message) {
  const { id, method, params } = message;

  if (method === 'initialize') {
    return sendResponse({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: {
          name: 'dev-crypto-toolkit',
          version: '1.0.0',
        },
      },
    });
  }

  if (method === 'notifications/initialized') {
    return; // no response needed
  }

  if (method === 'tools/list') {
    return sendResponse({
      jsonrpc: '2.0',
      id,
      result: { tools: TOOLS },
    });
  }

  if (method === 'tools/call') {
    const { name, arguments: args } = params;
    try {
      const result = executeTool(name, args || {});
      return sendResponse({
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        },
      });
    } catch (err) {
      return sendResponse({
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: `Error: ${err.message}` }],
          isError: true,
        },
      });
    }
  }

  // Unknown method
  sendResponse({
    jsonrpc: '2.0',
    id,
    error: { code: -32601, message: `Method not found: ${method}` },
  });
}

// Parse Content-Length framed messages from stdin
process.stdin.on('data', (chunk) => {
  buffer += chunk.toString();

  while (true) {
    const headerEnd = buffer.indexOf('\r\n\r\n');
    if (headerEnd === -1) break;

    const header = buffer.substring(0, headerEnd);
    const match = header.match(/Content-Length:\s*(\d+)/i);
    if (!match) {
      buffer = buffer.substring(headerEnd + 4);
      continue;
    }

    const contentLength = parseInt(match[1], 10);
    const bodyStart = headerEnd + 4;

    if (buffer.length < bodyStart + contentLength) break;

    const body = buffer.substring(bodyStart, bodyStart + contentLength);
    buffer = buffer.substring(bodyStart + contentLength);

    try {
      handleMessage(JSON.parse(body));
    } catch (err) {
      process.stderr.write(`Parse error: ${err.message}\n`);
    }
  }
});

process.stderr.write('dev-crypto-toolkit MCP server started (stdio)\n');
