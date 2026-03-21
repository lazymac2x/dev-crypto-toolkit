const express = require('express');
const cors = require('cors');
const tools = require('./tools');

const app = express();
const PORT = process.env.PORT || 4300;

app.use(cors());
app.use(express.json());

// ─── Health / Info ───────────────────────────────────────────────────────────

app.get('/', (_req, res) => {
  res.json({
    name: 'dev-crypto-toolkit',
    version: '1.0.0',
    description: 'Developer cryptography utilities REST API',
    endpoints: {
      'POST /api/v1/jwt/decode': 'Decode JWT token (without verification)',
      'POST /api/v1/hash': 'Hash a string (md5, sha1, sha256, sha512, hmac)',
      'POST /api/v1/base64/encode': 'Base64 encode',
      'POST /api/v1/base64/decode': 'Base64 decode',
      'POST /api/v1/url/encode': 'URL encode',
      'POST /api/v1/url/decode': 'URL decode',
      'GET /api/v1/uuid?count=5': 'Generate UUID v4',
      'GET /api/v1/password?length=16&count=5': 'Generate passwords',
      'POST /api/v1/timestamp': 'Convert timestamp formats',
      'GET /api/v1/random?bytes=32&format=hex': 'Generate random bytes',
      'POST /api/v1/password/hash': 'Hash password (pbkdf2)',
      'POST /api/v1/password/verify': 'Verify password against hash',
      'POST /api/v1/encode/rot13': 'ROT13 encode/decode',
      'POST /api/v1/encode/caesar': 'Caesar cipher',
    },
  });
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ─── Helper ──────────────────────────────────────────────────────────────────

function wrap(fn) {
  return (req, res) => {
    try {
      const result = fn(req);
      res.json({ success: true, data: result });
    } catch (err) {
      res.status(400).json({ success: false, error: err.message });
    }
  };
}

// ─── JWT ─────────────────────────────────────────────────────────────────────

app.post('/api/v1/jwt/decode', wrap((req) => {
  return tools.jwtDecode(req.body.token);
}));

// ─── Hash ────────────────────────────────────────────────────────────────────

app.post('/api/v1/hash', wrap((req) => {
  const { text, algorithm, key, encoding } = req.body;
  if (key || (algorithm && algorithm.toLowerCase() === 'hmac')) {
    return tools.hmac(text, key, req.body.hmacAlgorithm || 'sha256', encoding);
  }
  return tools.hash(text, algorithm, encoding);
}));

// ─── Base64 ──────────────────────────────────────────────────────────────────

app.post('/api/v1/base64/encode', wrap((req) => tools.base64Encode(req.body.text)));
app.post('/api/v1/base64/decode', wrap((req) => tools.base64Decode(req.body.text)));

// ─── URL Encode/Decode ───────────────────────────────────────────────────────

app.post('/api/v1/url/encode', wrap((req) => tools.urlEncode(req.body.text)));
app.post('/api/v1/url/decode', wrap((req) => tools.urlDecode(req.body.text)));

// ─── UUID ────────────────────────────────────────────────────────────────────

app.get('/api/v1/uuid', wrap((req) => tools.generateUUIDs(req.query.count)));

// ─── Password Generation ────────────────────────────────────────────────────

app.get('/api/v1/password', wrap((req) => {
  const { length, count, ...options } = req.query;
  // Convert string query params to booleans for options
  const opts = {};
  for (const [k, v] of Object.entries(options)) {
    opts[k] = v === 'true' || v === '1';
  }
  return tools.generatePasswords(length, count, opts);
}));

// ─── Password Hash / Verify ─────────────────────────────────────────────────

app.post('/api/v1/password/hash', wrap((req) => tools.passwordHash(req.body.password, req.body.iterations)));
app.post('/api/v1/password/verify', wrap((req) => tools.passwordVerify(req.body.password, req.body.hash)));

// ─── Random Bytes ────────────────────────────────────────────────────────────

app.get('/api/v1/random', wrap((req) => tools.randomBytes(req.query.bytes, req.query.format)));

// ─── Timestamp ───────────────────────────────────────────────────────────────

app.post('/api/v1/timestamp', wrap((req) => tools.timestampConvert(req.body.timestamp)));

// ─── String Encoding ─────────────────────────────────────────────────────────

app.post('/api/v1/encode/rot13', wrap((req) => tools.rot13(req.body.text)));
app.post('/api/v1/encode/caesar', wrap((req) => tools.caesarCipher(req.body.text, req.body.shift)));

// ─── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`dev-crypto-toolkit API running on http://localhost:${PORT}`);
});

module.exports = app;
