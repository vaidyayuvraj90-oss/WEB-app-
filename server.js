
/**
 * ElderEase — secure Node/Express backend (compatible with the supplied index.html)
 * -----------------------------------------------------------------------------
 * Requires Node.js >= 18, Express and cors (already present in package.json).
 * No additional npm packages and no separate database service are required.
 *
 * REQUIRED Render environment variables:
 *   GOOGLE_CLIENT_ID = your Google OAuth 2.0 WEB client ID (*.apps.googleusercontent.com)
 *   DEV_PASSWORD     = a NEW strong developer password (at least 12 characters)
 *
 * OPTIONAL:
 *   ALLOWED_ORIGINS     = comma-separated extra HTTPS frontend origins
 *   ELDEREASE_DATA_FILE = absolute file path for the server-side JSON store
 *
 * The Render service URL https://web-app-kkrx.onrender.com is an API BASE URL,
 * not a secret API key. The public Google client ID is returned by /api/config
 * to the existing index.html, so the HTML does not have to be modified again.
 *
 * SECURITY:
 * - Server verifies Google's RS256 ID-token signature using Google's JWKS,
 *   and checks issuer, audience, email verification and token lifetime.
 * - Random bearer sessions are stored server-side as SHA-256 hashes.
 * - All profile/booking operations use the user ID from the verified session.
 * - A public email, userId or typed-in profile can never authorize an action.
 * - The server DOES NOT serve database.json or other private repository files.
 * - Previous hardcoded/demo accounts and records are removed by migration.
 * - Developer access fails closed for missing/old demo passwords.
 *
 * IMPORTANT STORAGE LIMITATION:
 * Render's FREE web instances have an EPHEMERAL filesystem. database.json can
 * disappear after redeploy, restart, or spin-down. This is text-only server
 * storage, but NOT durable storage. For permanent records, a persistent volume
 * or an external database/storage provider will eventually be necessary.
 * Never commit database.json (it may contain personal data or session hashes).
 */
'use strict';

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim();
const DEV_PASSWORD = process.env.DEV_PASSWORD || '';
const DATA_FILE = path.resolve(process.env.ELDEREASE_DATA_FILE || path.join(__dirname, 'database.json'));
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

// A GitHub Pages PROJECT URL still has this exact origin (no repo path in CORS).
const allowedOrigins = new Set([
  'https://web-app-kkrx.onrender.com',
  'https://vaidyayuvraj90-oss.github.io',
  ...(process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean)
]);
if (process.env.NODE_ENV !== 'production') {
  allowedOrigins.add('http://localhost:3000');
  allowedOrigins.add('http://127.0.0.1:3000');
  allowedOrigins.add('http://localhost:5500');
  allowedOrigins.add('http://127.0.0.1:5500');
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'no-referrer');
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
  next();
});
app.use(cors({
  origin(origin, callback) {
    // Requests without Origin (e.g. health checks) are allowed; protected API
    // calls still require a valid bearer session or developer password.
    callback(null, !origin || allowedOrigins.has(origin));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type'],
  credentials: false,
  maxAge: 600
}));
app.use(express.json({ limit: '32kb' }));

function emptyStore() {
  return { users: [], bookings: [], sessions: [] };
}

function writeStore(data) {
  // Atomic replacement avoids partial/truncated JSON on interrupted writes.
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const temp = `${DATA_FILE}.${process.pid}.${crypto.randomBytes(5).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(temp, JSON.stringify(data, null, 2), { mode: 0o600 });
    fs.renameSync(temp, DATA_FILE);
  } finally {
    if (fs.existsSync(temp)) fs.unlinkSync(temp);
  }
}

function readStore() {
  if (!fs.existsSync(DATA_FILE)) {
    const initial = emptyStore(); // IMPORTANT: no preloaded dummy accounts.
    writeStore(initial);
    return initial;
  }
  // If a store is corrupt, do not overwrite users' data with an empty one.
  const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  if (!raw || !Array.isArray(raw.users) || !Array.isArray(raw.bookings)) {
    throw new Error('Invalid server record format.');
  }
  const data = {
    users: raw.users.filter(u => u && typeof u.googleSub === 'string' && u.googleSub.length > 0),
    bookings: raw.bookings,
    sessions: Array.isArray(raw.sessions) ? raw.sessions : []
  };
  // Discard all unverified legacy/demo accounts and any associated bookings.
  // Never let an old typed email impersonate a newly verified Google account.
  const authorizedIds = new Set(data.users.map(u => u.id));
  data.bookings = data.bookings.filter(b => b && authorizedIds.has(b.userId));
  data.sessions = data.sessions.filter(s =>
    s && authorizedIds.has(s.userId) && typeof s.tokenHash === 'string' &&
    Number(s.expiresAt) > Date.now()
  );
  return data;
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    picture: user.picture || avatarUrl(user.name),
    phone: user.phone || '',
    age: user.age || '',
    address: user.address || '',
    createdAt: user.createdAt,
    lastActive: user.lastActive
  };
}

function avatarUrl(name) {
  return `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=0369A1&color=fff&bold=true`;
}

function textField(value, maxLength = 200) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// -------------------------------- REAL GOOGLE SIGN-IN -----------------------
let keySet = [];
let keysExpireAt = 0;
async function googlePublicKeys(forceRefresh = false) {
  if (!forceRefresh && keySet.length && Date.now() < keysExpireAt) return keySet;
  const response = await fetch(GOOGLE_JWKS_URL, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error('Google public keys are unavailable');
  const body = await response.json();
  if (!Array.isArray(body.keys) || body.keys.length === 0) {
    throw new Error('Google returned no public keys');
  }
  const maxAge = Number(/max-age=(\d+)/.exec(response.headers.get('cache-control') || '')?.[1] || 300);
  keySet = body.keys;
  keysExpireAt = Date.now() + Math.min(3600, Math.max(60, maxAge)) * 1000;
  return keySet;
}

async function verifyGoogleCredential(credential) {
  if (!GOOGLE_CLIENT_ID) {
    const error = new Error('Set GOOGLE_CLIENT_ID in the Render environment to enable Google login.');
    error.status = 503;
    throw error;
  }
  if (typeof credential !== 'string' || credential.length < 100 || credential.length > 12000) {
    const error = new Error('A Google sign-in credential is required.');
    error.status = 400;
    throw error;
  }
  try {
    const parts = credential.split('.');
    if (parts.length !== 3) throw new Error('Invalid ID token');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new Error('Unsupported token algorithm');

    let keys = await googlePublicKeys();
    let jwk = keys.find(k => k.kid === header.kid && k.kty === 'RSA' && k.use === 'sig');
    if (!jwk) {
      keys = await googlePublicKeys(true); // Handles Google's signing key rotation.
      jwk = keys.find(k => k.kid === header.kid && k.kty === 'RSA' && k.use === 'sig');
    }
    if (!jwk) throw new Error('Unknown token signing key');
    const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const validSignature = crypto.verify(
      'RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), publicKey,
      Buffer.from(parts[2], 'base64url')
    );
    if (!validSignature) throw new Error('Invalid Google signature');

    const nowSeconds = Math.floor(Date.now() / 1000);
    if (!['accounts.google.com', 'https://accounts.google.com'].includes(claims.iss)) {
      throw new Error('Invalid token issuer');
    }
    if (claims.aud !== GOOGLE_CLIENT_ID || (claims.azp && claims.azp !== GOOGLE_CLIENT_ID)) {
      throw new Error('Token is for a different Google application');
    }
    if (typeof claims.exp !== 'number' || claims.exp <= nowSeconds ||
        typeof claims.iat !== 'number' || claims.iat > nowSeconds + 60 ||
        (typeof claims.nbf === 'number' && claims.nbf > nowSeconds + 60)) {
      throw new Error('Expired or invalid token lifetime');
    }
    if (!(claims.email_verified === true || claims.email_verified === 'true') ||
        typeof claims.email !== 'string' || !claims.email.includes('@') ||
        typeof claims.sub !== 'string' || !claims.sub ||
        typeof claims.name !== 'string' || !claims.name.trim()) {
      throw new Error('Google account is not verified');
    }
    return claims;
  } catch (error) {
    if (error.status) throw error;
    const invalid = new Error('Google sign-in was not verified. Please sign in again.');
    invalid.status = 401;
    // Errors contacting Google may be transient but never justify bypassing verification.
    throw invalid;
  }
}

function createSession(data, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + SESSION_TTL_MS;
  data.sessions = data.sessions.filter(s => s.userId !== userId).slice(-1999);
  data.sessions.push({ tokenHash: sha256(token), userId, expiresAt });
  return { token, expiresAt };
}

function authenticate(req, res, next) {
  const match = /^Bearer ([A-Za-z0-9_-]{40,200})$/.exec(req.get('Authorization') || '');
  if (!match) return res.status(401).json({ success: false, error: 'Google login required.' });
  const hash = sha256(match[1]);
  const data = readStore();
  const session = data.sessions.find(s => s.tokenHash === hash && s.expiresAt > Date.now());
  const user = session && data.users.find(u => u.id === session.userId);
  if (!user) return res.status(401).json({ success: false, error: 'Session expired. Please sign in again.' });
  req.account = user;
  req.sessionHash = hash;
  next();
}

// Public configuration: Google Web Client IDs are public identifiers, NOT keys.
app.get('/api/config', (_req, res) => {
  res.json({ googleClientId: GOOGLE_CLIENT_ID });
});

app.post('/api/auth/google', async (req, res, next) => {
  try {
    const claims = await verifyGoogleCredential(req.body?.credential);
    const data = readStore();
    const now = new Date().toISOString();
    let user = data.users.find(u => u.googleSub === claims.sub);
    if (!user) {
      user = {
        id: 'usr_' + sha256(claims.sub).slice(0, 24),
        googleSub: claims.sub,
        email: claims.email.toLowerCase(),
        name: textField(claims.name, 100),
        picture: /^https:\/\//.test(claims.picture || '') ? claims.picture : avatarUrl(claims.name),
        phone: '', age: '', address: '',
        createdAt: now, lastActive: now
      };
      data.users.unshift(user);
    } else {
      user.email = claims.email.toLowerCase();
      user.picture = /^https:\/\//.test(claims.picture || '') ? claims.picture : (user.picture || avatarUrl(user.name));
      user.lastActive = now;
      // Keep user's edited display name, mobile, age, and address unchanged.
    }
    const session = createSession(data, user.id);
    writeStore(data);
    res.json({ success: true, user: publicUser(user), token: session.token, expiresAt: session.expiresAt });
  } catch (error) { next(error); }
});

app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ success: true, user: publicUser(req.account) });
});

app.post('/api/auth/logout', authenticate, (req, res) => {
  const data = readStore();
  data.sessions = data.sessions.filter(s => s.tokenHash !== req.sessionHash);
  writeStore(data);
  res.json({ success: true });
});

// --------------------- PROFILE AND TEXT-ONLY BOOKINGS -----------------------
app.put('/api/user/profile', authenticate, (req, res) => {
  const data = readStore();
  const user = data.users.find(u => u.id === req.account.id);
  if (!user) return res.status(401).json({ success: false, error: 'Account no longer exists.' });
  const body = req.body || {};
  if (body.name !== undefined) {
    const name = textField(body.name, 100);
    if (!name) return res.status(400).json({ success: false, error: 'Name cannot be empty.' });
    user.name = name;
  }
  if (body.phone !== undefined) {
    const phone = textField(body.phone, 20);
    if (phone && !/^[0-9+() \-]{8,20}$/.test(phone)) {
      return res.status(400).json({ success: false, error: 'Invalid phone number.' });
    }
    user.phone = phone;
  }
  if (body.age !== undefined) {
    const age = textField(String(body.age ?? ''), 3);
    if (age && (!/^\d{1,3}$/.test(age) || Number(age) > 125 || Number(age) < 1)) {
      return res.status(400).json({ success: false, error: 'Invalid age.' });
    }
    user.age = age;
  }
  if (body.address !== undefined) user.address = textField(body.address, 250);
  user.lastActive = new Date().toISOString();
  writeStore(data);
  res.json({ success: true, user: publicUser(user) });
});

app.post('/api/bookings', authenticate, (req, res) => {
  const input = req.body || {};
  if (input.type && !['APPOINTMENT', 'VOLUNTEER'].includes(input.type)) {
    return res.status(400).json({ success: false, error: 'Invalid booking type.' });
  }
  const data = readStore();
  const user = data.users.find(u => u.id === req.account.id);
  if (!user) return res.status(401).json({ success: false, error: 'Account no longer exists.' });
  const type = input.type || 'APPOINTMENT';
  const name = textField(input.patientName, 100) || user.name;
  const phone = textField(input.phone, 20) || user.phone;
  const date = textField(input.date, 10);
  if (!name || !/^[0-9+() \-]{8,20}$/.test(phone)) {
    return res.status(400).json({ success: false, error: 'Patient name and a valid phone number are required.' });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(Date.parse(date + 'T00:00:00Z'))) {
    return res.status(400).json({ success: false, error: 'Please choose a valid booking date.' });
  }
  const now = Date.now();
  const booking = {
    id: 'EE-' + now.toString(36).toUpperCase() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
    userId: user.id,               // VERIFIED server-side identity, never from request body
    userEmail: user.email,
    userName: user.name,
    type,
    title: textField(input.title, 130) || (type === 'VOLUNTEER' ? 'Student Volunteer Home Visit' : 'Hospital Appointment'),
    patientName: name,
    phone,
    age: textField(String(input.age ?? user.age ?? ''), 3),
    department: textField(input.department, 120) || 'General Consultation',
    date,
    time: textField(input.time, 50) || 'Morning',
    reason: textField(input.reason, 500),
    createdAt: new Date(now).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
    timestamp: now
  };
  data.bookings.unshift(booking);
  user.lastActive = new Date(now).toISOString();
  if (!user.phone) user.phone = phone;
  if (!user.age && booking.age) user.age = booking.age;
  writeStore(data);
  // This records a REQUEST/slip; it does not reserve a slot with a hospital.
  res.status(201).json({ success: true, booking, user: publicUser(user) });
});

app.get('/api/bookings/me', authenticate, (req, res) => {
  const data = readStore();
  const bookings = data.bookings
    .filter(b => b.userId === req.account.id)
    .sort((a, b) => Number(b.timestamp || 0) - Number(a.timestamp || 0));
  res.json({ success: true, bookings });
});

app.delete('/api/bookings/:id', authenticate, (req, res) => {
  const data = readStore();
  const index = data.bookings.findIndex(b => b.id === req.params.id && b.userId === req.account.id);
  if (index < 0) return res.status(404).json({ success: false, error: 'Booking not found in your account.' });
  data.bookings.splice(index, 1);
  writeStore(data);
  res.json({ success: true });
});

// ---------------------------- DEVELOPER CONSOLE -----------------------------
// Do NOT leave the sample password ELDER2026 in render.yaml. It is already public.
// The developer console remains locked until a NEW strong DEV_PASSWORD is set.
const devAttempts = new Map();
app.post('/api/dev/overview', (req, res) => {
  if (DEV_PASSWORD.length < 12 || DEV_PASSWORD === 'ELDER2026') {
    return res.status(503).json({ success: false, error: 'Configure a new strong DEV_PASSWORD in Render.' });
  }
  const requester = req.ip || 'unknown';
  const now = Date.now();
  const entry = devAttempts.get(requester) || { count: 0, until: now + 15 * 60 * 1000 };
  if (now >= entry.until) { entry.count = 0; entry.until = now + 15 * 60 * 1000; }
  if (entry.count >= 8) return res.status(429).json({ success: false, error: 'Too many attempts. Try again later.' });
  const supplied = typeof req.body?.password === 'string' ? req.body.password : '';
  const suppliedHash = crypto.createHash('sha256').update(supplied).digest();
  const expectedHash = crypto.createHash('sha256').update(DEV_PASSWORD).digest();
  if (!crypto.timingSafeEqual(suppliedHash, expectedHash)) {
    entry.count++;
    devAttempts.set(requester, entry);
    return res.status(403).json({ success: false, error: 'Invalid Developer Key.' });
  }
  devAttempts.delete(requester);
  const data = readStore();
  const rankedUsers = data.users.map(user => {
    const bookings = data.bookings.filter(b => b.userId === user.id)
      .sort((a, b) => Number(b.timestamp || 0) - Number(a.timestamp || 0));
    const sortTime = Math.max(Date.parse(user.lastActive || user.createdAt) || 0,
      bookings[0] ? Number(bookings[0].timestamp || 0) : 0);
    return { ...publicUser(user), bookingCount: bookings.length, bookings, sortTime };
  }).sort((a, b) => b.sortTime - a.sortTime);
  res.json({ success: true, totalUsers: rankedUsers.length,
    totalBookings: data.bookings.length, users: rankedUsers });
});

// No express.static(__dirname): it would leak database.json, render.yaml etc.
// Keep existing support for index.html at repository root or under public/.
const rootIndex = path.join(__dirname, 'index.html');
const publicIndex = path.join(__dirname, 'public', 'index.html');
function serveHome(_req, res) {
  const chosen = fs.existsSync(publicIndex) ? publicIndex : rootIndex;
  if (!fs.existsSync(chosen)) return res.status(404).send('index.html not found');
  res.sendFile(chosen);
}
app.get(['/', '/index.html'], serveHome);
app.use('/api', (_req, res) => res.status(404).json({ success: false, error: 'API endpoint not found.' }));
app.use((_req, res) => res.status(404).send('Not found'));

app.use((error, _req, res, _next) => {
  if (error.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, error: 'Invalid JSON request.' });
  }
  if (error.type === 'entity.too.large') {
    return res.status(413).json({ success: false, error: 'Request too large.' });
  }
  if (!error.status || error.status >= 500) console.error('ElderEase server:', error.message);
  res.status(error.status || 500).json({ success: false,
    error: error.status && error.status < 500 ? error.message : 'Server could not complete your request.' });
});

if (require.main === module) {
  // Fail clearly if the data path is unreadable; never silently erase records.
  readStore();
  app.listen(PORT, () => {
    console.log(`ElderEase secure API listening on port ${PORT}`);
    console.log(`Google Client ID: ${GOOGLE_CLIENT_ID ? 'configured' : 'NOT configured'}`);
    console.log(`Developer password: ${DEV_PASSWORD.length >= 12 && DEV_PASSWORD !== 'ELDER2026' ? 'configured' : 'NOT securely configured'}`);
    console.log('Server-side JSON records are temporary on Render Free.');
  });
}

module.exports = app; // Allows isolated testing without starting the server.
