# dev-crypto-toolkit

Developer cryptography utilities — REST API + MCP server.

All operations use Node.js built-in `crypto` module. No external APIs, no secrets leave your machine.

## Features

- **JWT** — Decode tokens (inspect header/payload without verification)
- **Hash** — MD5, SHA1, SHA256, SHA512, HMAC
- **Base64** — Encode / Decode
- **URL** — Encode / Decode
- **UUID** — v4 generation (bulk)
- **Password** — Generation with configurable length & complexity
- **Random** — Cryptographically secure hex/bytes/base64
- **Password Hashing** — PBKDF2-SHA512 hash & verify
- **Timestamp** — Unix ↔ ISO ↔ human readable conversion
- **String Encoding** — ROT13, Caesar cipher

## Quick Start

```bash
npm install
npm start        # REST API on http://localhost:4300
npm run mcp      # MCP server (stdio)
```

## Docker

```bash
docker build -t dev-crypto-toolkit .
docker run -p 4300:4300 dev-crypto-toolkit
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/jwt/decode` | Decode JWT token |
| POST | `/api/v1/hash` | Hash string (md5/sha1/sha256/sha512/hmac) |
| POST | `/api/v1/base64/encode` | Base64 encode |
| POST | `/api/v1/base64/decode` | Base64 decode |
| POST | `/api/v1/url/encode` | URL encode |
| POST | `/api/v1/url/decode` | URL decode |
| GET | `/api/v1/uuid?count=5` | Generate UUIDs |
| GET | `/api/v1/password?length=16&count=5` | Generate passwords |
| POST | `/api/v1/password/hash` | Hash password (PBKDF2) |
| POST | `/api/v1/password/verify` | Verify password hash |
| GET | `/api/v1/random?bytes=32&format=hex` | Random bytes |
| POST | `/api/v1/timestamp` | Convert timestamps |
| POST | `/api/v1/encode/rot13` | ROT13 |
| POST | `/api/v1/encode/caesar` | Caesar cipher |

## MCP Configuration

Add to your MCP client config:

```json
{
  "mcpServers": {
    "dev-crypto-toolkit": {
      "command": "node",
      "args": ["/path/to/dev-crypto-toolkit/src/mcp-server.js"]
    }
  }
}
```

## Examples

```bash
# Decode JWT
curl -s -X POST http://localhost:4300/api/v1/jwt/decode \
  -H 'Content-Type: application/json' \
  -d '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}'

# SHA256 hash
curl -s -X POST http://localhost:4300/api/v1/hash \
  -H 'Content-Type: application/json' \
  -d '{"text":"hello world","algorithm":"sha256"}'

# Generate 5 UUIDs
curl -s 'http://localhost:4300/api/v1/uuid?count=5'

# Generate passwords
curl -s 'http://localhost:4300/api/v1/password?length=24&count=3'

# Timestamp conversion
curl -s -X POST http://localhost:4300/api/v1/timestamp \
  -H 'Content-Type: application/json' \
  -d '{"timestamp":1700000000}'
```

## License

MIT
