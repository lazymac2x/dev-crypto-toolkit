const crypto = require('crypto');

// ─── JWT Decode (without verification) ───────────────────────────────────────

function jwtDecode(token) {
  if (!token || typeof token !== 'string') {
    throw new Error('Invalid token: must be a non-empty string');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT: must have 3 parts separated by dots');
  }

  const decodeSegment = (seg) => {
    const padded = seg.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  };

  const header = decodeSegment(parts[0]);
  const payload = decodeSegment(parts[1]);

  const result = { header, payload };

  // Add human-readable timestamps if present
  if (payload.iat) result.issuedAt = new Date(payload.iat * 1000).toISOString();
  if (payload.exp) {
    result.expiresAt = new Date(payload.exp * 1000).toISOString();
    result.expired = Date.now() / 1000 > payload.exp;
  }
  if (payload.nbf) result.notBefore = new Date(payload.nbf * 1000).toISOString();

  return result;
}

// ─── Hash ────────────────────────────────────────────────────────────────────

function hash(text, algorithm = 'sha256', encoding = 'hex') {
  const supported = ['md5', 'sha1', 'sha256', 'sha512'];
  const algo = algorithm.toLowerCase();
  if (!supported.includes(algo)) {
    throw new Error(`Unsupported algorithm: ${algorithm}. Supported: ${supported.join(', ')}`);
  }
  if (!text && text !== '') {
    throw new Error('Text is required');
  }
  return {
    algorithm: algo,
    hash: crypto.createHash(algo).update(String(text)).digest(encoding),
    encoding,
  };
}

function hmac(text, key, algorithm = 'sha256', encoding = 'hex') {
  const supported = ['md5', 'sha1', 'sha256', 'sha512'];
  const algo = algorithm.toLowerCase();
  if (!supported.includes(algo)) {
    throw new Error(`Unsupported algorithm: ${algorithm}. Supported: ${supported.join(', ')}`);
  }
  if (!text && text !== '') throw new Error('Text is required');
  if (!key) throw new Error('Key is required for HMAC');

  return {
    algorithm: algo,
    hmac: crypto.createHmac(algo, String(key)).update(String(text)).digest(encoding),
    encoding,
  };
}

// ─── Base64 ──────────────────────────────────────────────────────────────────

function base64Encode(text) {
  if (text === undefined || text === null) throw new Error('Text is required');
  return { encoded: Buffer.from(String(text)).toString('base64') };
}

function base64Decode(encoded) {
  if (!encoded) throw new Error('Encoded string is required');
  const decoded = Buffer.from(String(encoded), 'base64').toString('utf8');
  return { decoded };
}

// ─── URL Encode/Decode ───────────────────────────────────────────────────────

function urlEncode(text) {
  if (text === undefined || text === null) throw new Error('Text is required');
  return { encoded: encodeURIComponent(String(text)) };
}

function urlDecode(encoded) {
  if (!encoded) throw new Error('Encoded string is required');
  return { decoded: decodeURIComponent(String(encoded)) };
}

// ─── UUID v4 ─────────────────────────────────────────────────────────────────

function generateUUIDs(count = 1) {
  const n = Math.min(Math.max(1, parseInt(count, 10) || 1), 1000);
  const uuids = [];
  for (let i = 0; i < n; i++) {
    uuids.push(crypto.randomUUID());
  }
  return { count: n, uuids };
}

// ─── Password Generation ────────────────────────────────────────────────────

function generatePasswords(length = 16, count = 1, options = {}) {
  const len = Math.min(Math.max(4, parseInt(length, 10) || 16), 256);
  const n = Math.min(Math.max(1, parseInt(count, 10) || 1), 100);

  const charsets = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  };

  let chars = '';
  const include = {
    lowercase: options.lowercase !== false,
    uppercase: options.uppercase !== false,
    digits: options.digits !== false,
    symbols: options.symbols !== false,
  };

  for (const [key, enabled] of Object.entries(include)) {
    if (enabled) chars += charsets[key];
  }

  if (!chars) chars = charsets.lowercase + charsets.uppercase + charsets.digits;

  const passwords = [];
  for (let i = 0; i < n; i++) {
    const bytes = crypto.randomBytes(len);
    let password = '';
    for (let j = 0; j < len; j++) {
      password += chars[bytes[j] % chars.length];
    }
    passwords.push(password);
  }

  return { count: n, length: len, options: include, passwords };
}

// ─── Random Bytes ────────────────────────────────────────────────────────────

function randomBytes(bytes = 32, format = 'hex') {
  const n = Math.min(Math.max(1, parseInt(bytes, 10) || 32), 1024);
  const fmt = format.toLowerCase();

  const buf = crypto.randomBytes(n);

  let value;
  if (fmt === 'hex') {
    value = buf.toString('hex');
  } else if (fmt === 'base64') {
    value = buf.toString('base64');
  } else if (fmt === 'array') {
    value = Array.from(buf);
  } else {
    throw new Error('Unsupported format. Use: hex, base64, array');
  }

  return { bytes: n, format: fmt, value };
}

// ─── Bcrypt-style Password Hashing (pbkdf2) ─────────────────────────────────

function passwordHash(password, iterations = 100000) {
  if (!password) throw new Error('Password is required');
  const salt = crypto.randomBytes(16).toString('hex');
  const iter = Math.max(10000, parseInt(iterations, 10) || 100000);
  const derived = crypto.pbkdf2Sync(String(password), salt, iter, 64, 'sha512').toString('hex');

  return {
    hash: `$pbkdf2-sha512$${iter}$${salt}$${derived}`,
    salt,
    iterations: iter,
    algorithm: 'pbkdf2-sha512',
  };
}

function passwordVerify(password, hashString) {
  if (!password || !hashString) throw new Error('Password and hash are required');

  const parts = hashString.split('$').filter(Boolean);
  if (parts.length !== 4 || parts[0] !== 'pbkdf2-sha512') {
    throw new Error('Invalid hash format. Expected $pbkdf2-sha512$iterations$salt$hash');
  }

  const [, iterations, salt, originalHash] = parts;
  const derived = crypto.pbkdf2Sync(String(password), salt, parseInt(iterations, 10), 64, 'sha512').toString('hex');

  return {
    match: crypto.timingSafeEqual(Buffer.from(derived, 'hex'), Buffer.from(originalHash, 'hex')),
  };
}

// ─── Timestamp Conversion ────────────────────────────────────────────────────

function timestampConvert(input) {
  if (input === undefined || input === null) throw new Error('Timestamp input is required');

  let date;
  const val = typeof input === 'string' ? input.trim() : input;

  if (typeof val === 'number' || /^\d+$/.test(val)) {
    const num = Number(val);
    // If less than 1e12, treat as seconds; otherwise milliseconds
    date = num < 1e12 ? new Date(num * 1000) : new Date(num);
  } else {
    date = new Date(val);
  }

  if (isNaN(date.getTime())) {
    throw new Error('Invalid timestamp or date string');
  }

  return {
    unix: Math.floor(date.getTime() / 1000),
    unixMs: date.getTime(),
    iso: date.toISOString(),
    utc: date.toUTCString(),
    human: date.toLocaleString('en-US', { dateStyle: 'full', timeStyle: 'long', timeZone: 'UTC' }),
    date: {
      year: date.getUTCFullYear(),
      month: date.getUTCMonth() + 1,
      day: date.getUTCDate(),
      hour: date.getUTCHours(),
      minute: date.getUTCMinutes(),
      second: date.getUTCSeconds(),
    },
  };
}

// ─── String Encoding: ROT13 / Caesar ─────────────────────────────────────────

function rot13(text) {
  if (text === undefined || text === null) throw new Error('Text is required');
  return {
    result: String(text).replace(/[a-zA-Z]/g, (c) => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    }),
  };
}

function caesarCipher(text, shift = 3) {
  if (text === undefined || text === null) throw new Error('Text is required');
  const s = ((parseInt(shift, 10) || 3) % 26 + 26) % 26;
  return {
    result: String(text).replace(/[a-zA-Z]/g, (c) => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + s) % 26) + base);
    }),
    shift: s,
  };
}

// ─── Exports ─────────────────────────────────────────────────────────────────

module.exports = {
  jwtDecode,
  hash,
  hmac,
  base64Encode,
  base64Decode,
  urlEncode,
  urlDecode,
  generateUUIDs,
  generatePasswords,
  randomBytes,
  passwordHash,
  passwordVerify,
  timestampConvert,
  rot13,
  caesarCipher,
};
