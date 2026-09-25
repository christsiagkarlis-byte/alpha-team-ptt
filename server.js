require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const { createClient } = require('redis');
const { Server } = require('socket.io');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const INCIDENT_CODES = Object.freeze(require('./public/incident-codes.json'));
const INCIDENT_CODE_MAP = new Map(INCIDENT_CODES.map((item) => [item.code, item.label]));
const CRITICAL_INCIDENT_CODES = new Set(['EVACUATION', '0-01', '0-02', '0-05', '0-11', '0-13', '0-15', '0-21', '0-22', '0-23', '0-50', '0-70', '0-80', '0-100', '0-166', '0-199', 'MEDICAL_EMERGENCY', 'LOSS_OF_CONSCIOUSNESS', 'FIRE_OR_SMOKE', 'HAZARDOUS_LEAK', 'EMERGENCY_EXIT_BREACH', 'MISSING_CHILD_OR_VULNERABLE_PERSON', 'AGGRESSIVE_BEHAVIOR_OR_THREAT', 'SUSPICIOUS_PACKAGE']);

function readSecretValue(name) {
  const fileName = `${name}_FILE`;
  if (process.env[fileName]) {
    try {
      const value = fs.readFileSync(process.env[fileName], 'utf8').replace(/\r?\n$/, '');
      if (!value) throw new Error('empty secret file');
      return value;
    } catch (error) {
      throw new Error(`Unable to load configured secret ${name}`);
    }
  }
  return process.env[name];
}

for (const secretName of ['DATABASE_URL', 'REDIS_URL', 'JWT_SECRET', 'ADMIN_API_KEY', 'ACCESS_CODE', 'PGPASSWORD', 'REDIS_PASSWORD']) {
  const value = readSecretValue(secretName);
  if (value) process.env[secretName] = value;
}
if (!process.env.DATABASE_URL && process.env.PGHOST && process.env.PGUSER && process.env.PGDATABASE && process.env.PGPASSWORD) {
  const user = encodeURIComponent(process.env.PGUSER);
  const password = encodeURIComponent(process.env.PGPASSWORD);
  const host = process.env.PGHOST;
  const port = Number.parseInt(process.env.PGPORT || '5432', 10);
  process.env.DATABASE_URL = `postgresql://${user}:${password}@${host}:${port}/${encodeURIComponent(process.env.PGDATABASE)}`;
}
if (!process.env.REDIS_URL && process.env.REDIS_HOST && process.env.REDIS_PASSWORD) {
  const host = process.env.REDIS_HOST;
  const port = Number.parseInt(process.env.REDIS_PORT || '6379', 10);
  process.env.REDIS_URL = `redis://:${encodeURIComponent(process.env.REDIS_PASSWORD)}@${host}:${port}`;
}

function boundedInteger(name, fallback, minimum, maximum) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return parsed;
}

const requiredEnvironment = ['DATABASE_URL', 'REDIS_URL', 'JWT_SECRET', 'ADMIN_API_KEY', 'ACCESS_CODE'];
for (const key of requiredEnvironment) {
  if (!process.env[key]) throw new Error(`Missing required runtime configuration: ${key}`);
}
if (process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters long');
if (process.env.ADMIN_API_KEY.length < 24) throw new Error('ADMIN_API_KEY must be at least 24 characters long');

const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = boundedInteger('PORT', 3000, 1, 65535);
const ACTIVATION_TTL_SECONDS = boundedInteger('ACTIVATION_TTL_SECONDS', 600, 60, 86400);
const STATUS_TTL_SECONDS = boundedInteger('REDIS_STATUS_TTL_SECONDS', 120, 30, 3600);
const PTT_LOCK_TTL_SECONDS = boundedInteger('PTT_LOCK_TTL_SECONDS', 30, 5, 300);
const JWT_ISSUER = process.env.JWT_ISSUER || 'alpha-team-ptt';
const SESSION_TTL_SECONDS = boundedInteger('SESSION_TTL_SECONDS', 86400, 300, 604800);
const ADMIN_RATE_LIMIT_WINDOW_MS = boundedInteger('ADMIN_RATE_LIMIT_WINDOW_SECONDS', 60, 10, 3600) * 1000;
const ADMIN_RATE_LIMIT_MAX = boundedInteger('ADMIN_RATE_LIMIT_MAX', 20, 1, 1000);
const SOCKET_CONNECTION_LIMIT = boundedInteger('SOCKET_CONNECTION_LIMIT', 30, 1, 10000);
const SOCKET_EVENT_WINDOW_SECONDS = boundedInteger('SOCKET_EVENT_WINDOW_SECONDS', 60, 1, 3600);
const SOCKET_EVENT_LIMIT = boundedInteger('SOCKET_EVENT_LIMIT', 180, 10, 10000);
const SOCKET_LOCATION_MIN_INTERVAL_MS = boundedInteger('SOCKET_LOCATION_MIN_INTERVAL_MS', 5000, 1000, 60000);
const SOCKET_LOCATION_LIMIT = boundedInteger('SOCKET_LOCATION_LIMIT', 24, 1, 600);
const SOCKET_INCIDENT_LIMIT = boundedInteger('SOCKET_INCIDENT_LIMIT', 8, 1, 100);
const SOCKET_SIGNAL_LIMIT = boundedInteger('SOCKET_SIGNAL_LIMIT', 90, 1, 1000);
const SOCKET_PTT_START_LIMIT = boundedInteger('SOCKET_PTT_START_LIMIT', 24, 1, 600);
const RETENTION_INTERVAL_SECONDS = boundedInteger('RETENTION_INTERVAL_SECONDS', 3600, 300, 86400);
const RETENTION_BATCH_SIZE = boundedInteger('RETENTION_BATCH_SIZE', 1000, 10, 10000);
const STORAGE_MONITOR_INTERVAL_SECONDS = boundedInteger('STORAGE_MONITOR_INTERVAL_SECONDS', 21600, 300, 86400);
const STORAGE_WARNING_BYTES = boundedInteger('STORAGE_WARNING_BYTES', 5368709120, 1048576, 1099511627776);
const RETENTION_DAYS = Object.freeze({
  audit: boundedInteger('AUDIT_RETENTION_DAYS', 365, 30, 3650),
  incidents: boundedInteger('INCIDENT_RETENTION_DAYS', 365, 30, 3650),
  legacyIncidents: boundedInteger('LEGACY_INCIDENT_RETENTION_DAYS', 180, 30, 3650),
  locations: boundedInteger('LOCATION_HISTORY_RETENTION_DAYS', 30, 1, 365),
  wellbeing: boundedInteger('WELLBEING_RETENTION_DAYS', 90, 7, 3650),
  notifications: boundedInteger('NOTIFICATION_RETENTION_DAYS', 90, 7, 3650),
  scans: boundedInteger('SCAN_RETENTION_DAYS', 180, 7, 3650),
  activation: boundedInteger('ACTIVATION_TOKEN_RETENTION_DAYS', 7, 1, 365),
  subscriptions: boundedInteger('PUSH_SUBSCRIPTION_RETENTION_DAYS', 180, 30, 3650)
});
const DEFAULT_CHANNEL_ID = 'alpha-team';
const CORS_ORIGINS = process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map((value) => value.trim()).filter(Boolean) : [];
const RP_NAME = process.env.WEBAUTHN_RP_NAME || 'Team Stadium';
const RP_ID = process.env.WEBAUTHN_RP_ID || (CORS_ORIGINS[0] ? new URL(CORS_ORIGINS[0]).hostname : 'localhost');
const EXPECTED_ORIGIN = process.env.WEBAUTHN_ORIGIN || (CORS_ORIGINS[0] || `http://localhost:${PORT}`);
if (NODE_ENV === 'production' && (!EXPECTED_ORIGIN.startsWith('https://') || RP_ID === 'localhost')) {
  throw new Error('Production WebAuthn requires a public HTTPS WEBAUTHN_ORIGIN and non-localhost WEBAUTHN_RP_ID');
}
if (NODE_ENV === 'production' && CORS_ORIGINS.some((origin) => !origin.startsWith('https://'))) {
  throw new Error('Production CORS_ORIGIN values must use HTTPS');
}
const PREDEFINED_USERNAMES = Object.freeze([
  'ALFA', 'Bravo', 'Charlie', 'Delta', 'Echo', 'Foxtrot', 'Golf', 'Hotel', 'India', 'Juliet',
  'Kilo', 'Lima', 'Mike', 'November', 'Oscar', 'Papa', 'Romeo', 'Quadec', 'Sierra', 'Tango',
  'Uniform', 'Victor', 'Whisky', 'X-ray', 'Yankee', 'Zulu', 'Sentinel', 'Patrol', 'Response',
  'Guardian', 'Control'
]);
const app = express();
const httpServer = http.createServer(app);
app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : false);
app.disable('x-powered-by');
app.use((req, res, next) => {
  req.requestId = requestId();
  res.setHeader('x-request-id', req.requestId);
  next();
});
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://unpkg.com'],
      styleSrc: ["'self'", 'https://unpkg.com', "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https://*.tile.openstreetmap.org'],
      connectSrc: ["'self'", 'wss:', 'https:'],
      mediaSrc: ["'self'", 'blob:'],
      workerSrc: ["'self'", 'blob:'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'no-referrer' }
}));
app.use(express.json({ limit: '32kb' }));
app.use('/api', (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many authentication attempts; try again later' } });
const sensitiveLimiter = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many requests; try again later' } });
const adminLimiter = rateLimit({ windowMs: ADMIN_RATE_LIMIT_WINDOW_MS, limit: ADMIN_RATE_LIMIT_MAX, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Administrative request quota exceeded; try again later' } });
const io = new Server(httpServer, {
  cors: {
    origin: CORS_ORIGINS.length ? CORS_ORIGINS : false,
    methods: ['GET', 'POST']
  },
  transports: ['websocket', 'polling'],
  maxHttpBufferSize: 16 * 1024
});
app.use(express.static('public'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: true } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', (error) => console.error('Redis error:', error.message));

const RATE_LIMIT_SCRIPT = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
`;

function rateLimitIdentifier(value) {
  return crypto.createHash('sha256').update(String(value)).digest('base64url').slice(0, 32);
}

async function consumeQuota(scope, subject, limit, windowSeconds) {
  const key = `ptt:quota:${scope}:${rateLimitIdentifier(subject)}`;
  const result = await redis.eval(RATE_LIMIT_SCRIPT, { keys: [key], arguments: [String(windowSeconds)] });
  const count = Number(result?.[0] || 0);
  const retryAfterSeconds = Math.max(1, Number(result?.[1] || windowSeconds));
  return { allowed: count <= limit, count, limit, retryAfterSeconds };
}

const SOCKET_EVENT_POLICIES = Object.freeze({
  location_update: { limit: SOCKET_LOCATION_LIMIT, windowSeconds: SOCKET_EVENT_WINDOW_SECONDS, minIntervalMs: SOCKET_LOCATION_MIN_INTERVAL_MS },
  location_stop: { limit: 30, windowSeconds: SOCKET_EVENT_WINDOW_SECONDS, minIntervalMs: 250 },
  incident_report: { limit: SOCKET_INCIDENT_LIMIT, windowSeconds: SOCKET_EVENT_WINDOW_SECONDS, minIntervalMs: 1000 },
  ptt_join: { limit: 30, windowSeconds: SOCKET_EVENT_WINDOW_SECONDS, minIntervalMs: 250 },
  ptt_start: { limit: SOCKET_PTT_START_LIMIT, windowSeconds: SOCKET_EVENT_WINDOW_SECONDS, minIntervalMs: 500 },
  ptt_stop: { limit: 120, windowSeconds: SOCKET_EVENT_WINDOW_SECONDS, minIntervalMs: 100 },
  webrtc_offer: { limit: SOCKET_SIGNAL_LIMIT, windowSeconds: SOCKET_EVENT_WINDOW_SECONDS, minIntervalMs: 0 },
  webrtc_answer: { limit: SOCKET_SIGNAL_LIMIT, windowSeconds: SOCKET_EVENT_WINDOW_SECONDS, minIntervalMs: 0 },
  webrtc_ice_candidate: { limit: SOCKET_SIGNAL_LIMIT, windowSeconds: SOCKET_EVENT_WINDOW_SECONDS, minIntervalMs: 0 }
});

async function enforceSocketEventPolicy(socket, eventName) {
  const policy = SOCKET_EVENT_POLICIES[eventName] || { limit: SOCKET_EVENT_LIMIT, windowSeconds: SOCKET_EVENT_WINDOW_SECONDS, minIntervalMs: 0 };
  const now = Date.now();
  const lastEventAt = socket.data.lastEventAt || new Map();
  const previous = lastEventAt.get(eventName) || 0;
  if (policy.minIntervalMs > 0 && now - previous < policy.minIntervalMs) {
    return { allowed: false, reason: 'event_frequency', retryAfterSeconds: Math.ceil((policy.minIntervalMs - (now - previous)) / 1000) };
  }
  const quota = await consumeQuota(`socket:${eventName}`, `user:${socket.data.user.id}`, policy.limit, policy.windowSeconds);
  if (!quota.allowed) return { ...quota, reason: 'event_quota' };
  lastEventAt.set(eventName, now);
  socket.data.lastEventAt = lastEventAt;
  return quota;
}

function socketClientAddress(socket) {
  const forwarded = process.env.TRUST_PROXY === 'true' ? socket.handshake.headers?.['x-forwarded-for'] : null;
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim().slice(0, 128);
  return String(socket.handshake.address || 'unknown').slice(0, 128);
}

const LOCK_ACQUIRE_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if current then
  return {0, current}
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return {1, ''}
`;

const LEADER_OVERRIDE_SCRIPT = `
local current = redis.call('GET', KEYS[1])
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
if current then
  return {1, current}
end
return {1, ''}
`;

const RELEASE_LOCK_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if current == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
`;

function requestId() {
  return crypto.randomUUID();
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function isAdminKeyValid(provided) {
  if (!provided || typeof provided !== 'string') return false;
  const configured = process.env.ADMIN_API_KEY;
  if (configured.startsWith('$2b$') || configured.startsWith('$2a$') || configured.startsWith('$2y$')) return bcrypt.compare(provided, configured);
  return safeEqual(provided, configured);
}

async function accessCodeMatches(candidate) {
  if (typeof candidate !== 'string' || !candidate) return false;
  if (/^\$2[aby]\$/.test(process.env.ACCESS_CODE)) return bcrypt.compare(candidate, process.env.ACCESS_CODE);
  return safeEqual(candidate, process.env.ACCESS_CODE);
}

function sessionToken(user, hardwareUuid) {
  return jwt.sign({ typ: 'device_session', sub: String(user.id), username: user.username, role: user.role, hardware_uuid: hardwareUuid, session_version: Number(user.session_version) }, process.env.JWT_SECRET, {
    algorithm: 'HS256', expiresIn: SESSION_TTL_SECONDS, issuer: JWT_ISSUER, audience: 'alpha-team-session'
  });
}

class SessionValidationError extends Error {}

function readSessionToken(value, authorization = '') {
  if (typeof value === 'string' && value.length > 0 && value.length <= 8192) return value;
  const token = authorization.replace(/^Bearer\s+/i, '').trim();
  return token.length > 0 && token.length <= 8192 ? token : '';
}

async function resolveDeviceSession(token, expected = {}) {
  let claims;
  try {
    claims = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'], issuer: JWT_ISSUER, audience: 'alpha-team-session' });
  } catch (_) {
    throw new SessionValidationError('Device session signature is invalid or expired');
  }
  if (claims.typ !== 'device_session' || !claims.sub || !claims.username || !claims.hardware_uuid || !Number.isInteger(Number(claims.session_version))) {
    throw new SessionValidationError('Device session claims are incomplete');
  }
  if ((expected.username && claims.username !== expected.username) || (expected.hardwareUuid && claims.hardware_uuid !== expected.hardwareUuid)) {
    throw new SessionValidationError('Device session does not match the connection binding');
  }
  const result = await pool.query(
    'SELECT id, username, role, hardware_uuid, is_active, session_version FROM users WHERE id = $1 AND username = $2',
    [claims.sub, claims.username]
  );
  const user = result.rows[0];
  if (!user || !user.is_active || user.hardware_uuid !== claims.hardware_uuid || Number(user.session_version) !== Number(claims.session_version)) {
    throw new SessionValidationError('Device session has been revoked or binding was reset');
  }
  return { user, claims };
}

async function verifySession(req, res, next) {
  try {
    const token = readSessionToken(req.body?.session_token, req.get('authorization') || '');
    const authenticated = await resolveDeviceSession(token);
    req.sessionUser = authenticated.user;
    req.sessionClaims = authenticated.claims;
    return next();
  } catch (_) {
    return res.status(401).json({ error: 'Valid, non-revoked device session is required' });
  }
}

const WEBRTC_ICE_SERVERS = (() => {
  try {
    const parsed = JSON.parse(process.env.WEBRTC_ICE_SERVERS_JSON || '[]');
    return Array.isArray(parsed) ? parsed.slice(0, 8) : [];
  } catch (_) {
    return [];
  }
})();

app.post('/api/webrtc/config', verifySession, (req, res) => {
  return res.json({ ice_servers: [{ urls: 'stun:stun.l.google.com:19302' }, ...WEBRTC_ICE_SERVERS] });
});

function leaderOnly(req, res, next) {
  if (req.sessionUser?.username !== 'ALFA' || req.sessionUser?.role !== 'leader') return res.status(403).json({ error: 'Only ALFA may perform this action' });
  return next();
}

function normalizeUsername(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeHardwareUuid(value) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, 255);
}

function normalizeChannelId(value) {
  if (typeof value !== 'string') return '';
  const channelId = value.trim();
  return /^[A-Za-z0-9:_-]{1,128}$/.test(channelId) ? channelId : '';
}

function parsePageLimit(value, defaultLimit = 50, maximum = 100) {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) ? Math.min(Math.max(parsed, 1), maximum) : defaultLimit;
}

function parseCursor(value) {
  if (typeof value !== 'string' || value.length < 4 || value.length > 256) return null;
  try {
    const decoded = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
    const id = Number(decoded.id);
    const createdAt = new Date(String(decoded.created_at));
    if (!Number.isSafeInteger(id) || id < 1 || Number.isNaN(createdAt.getTime())) return null;
    return { id, created_at: String(decoded.created_at) };
  } catch (_) {
    return null;
  }
}

function encodeCursor(row) {
  const createdAt = row.cursor_created_at || new Date(row.created_at).toISOString();
  return Buffer.from(JSON.stringify({ id: Number(row.id), created_at: createdAt })).toString('base64url');
}

function auditPayload(req, extra = {}) {
  return { ...extra, user_agent: req.get('user-agent') || null, remote_address: req.ip || null };
}

async function writeAudit(client, eventType, req, user, metadata = {}) {
  await client.query(
    `INSERT INTO audit_events (event_type, username, user_id, request_id, ip_address, metadata)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
    [eventType, user?.username || null, user?.id || null, req.requestId, req.ip || null, JSON.stringify(auditPayload(req, metadata))]
  );
}

async function setDeviceStatus(user, hardwareUuid, status = 'online', killSwitch = false) {
  const key = `ptt:status:${user.username}`;
  await redis.hSet(key, {
    status,
    hardware_bound: hardwareUuid ? 'true' : 'false',
    current_device_uuid: hardwareUuid || '',
    user_id: String(user.id),
    username: user.username,
    role: user.role,
    kill_switch: killSwitch ? 'true' : 'false',
    updated_at: new Date().toISOString()
  });
  await redis.expire(key, STATUS_TTL_SECONDS);
}

async function getCurrentTransmittingUsers() {
  const currentChannels = new Map();
  for await (const key of redis.scanIterator({ MATCH: 'ptt:channel:*:lock', COUNT: 100 })) {
    const lock = parseLockValue(await redis.get(key));
    if (lock?.username && lock.channel_id) currentChannels.set(lock.username, lock.channel_id);
  }
  return currentChannels;
}

async function getDashboardProfiles() {
  const result = await pool.query(
    `SELECT id, username, role, is_active, hardware_uuid
     FROM users
     WHERE username = ANY($1::text[])
     ORDER BY id ASC`,
    [PREDEFINED_USERNAMES]
  );
  const currentChannels = await getCurrentTransmittingUsers();
  const profiles = await Promise.all(result.rows.map(async (user) => {
    const realtime = await redis.hGetAll(`ptt:status:${user.username}`);
    const online = user.is_active && user.hardware_uuid !== null && realtime.status === 'online';
    return {
      username: user.username,
      role: user.role,
      active: user.is_active,
      status: online ? 'online' : 'offline',
      current_channel: currentChannels.get(user.username) || null,
      hardware_bound: user.hardware_uuid !== null && realtime.hardware_bound !== 'false',
      device_uuid: user.hardware_uuid,
      realtime_updated_at: realtime.updated_at || null,
      kill_switch: realtime.kill_switch === 'true' || !user.is_active
    };
  }));
  return profiles;
}

async function broadcastPresence() {
  try {
    const profiles = await getDashboardProfiles();
    io.emit('presence_update', { profiles, emitted_at: new Date().toISOString() });
  } catch (error) {
    console.error('Presence broadcast failed:', error.message);
  }
}

const GEO_LIMITS = Object.freeze({
  minLatitude: -90,
  maxLatitude: 90,
  minLongitude: -180,
  maxLongitude: 180,
  maxAccuracyMeters: 100000,
  maxCheckpointRadiusMeters: 10000,
  maxGeofenceRadiusMeters: 100000,
  maxSpeedMetersPerSecond: 150,
  maxHeadingDegrees: 360
});

function finiteNumber(value) {
  if (value === '' || value === null || value === undefined || typeof value === 'boolean') return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizeLocationPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const latitude = finiteNumber(payload.latitude);
  const longitude = finiteNumber(payload.longitude);
  const accuracy = payload.accuracy_m == null ? null : finiteNumber(payload.accuracy_m);
  if (latitude === null || latitude < GEO_LIMITS.minLatitude || latitude > GEO_LIMITS.maxLatitude) return null;
  if (longitude === null || longitude < GEO_LIMITS.minLongitude || longitude > GEO_LIMITS.maxLongitude) return null;
  if (accuracy !== null && (accuracy < 0 || accuracy > GEO_LIMITS.maxAccuracyMeters)) return null;
  return { latitude, longitude, accuracy_m: accuracy };
}

function parseOptionalLocation(payload) {
  if (payload === null || payload === undefined) return { valid: true, value: null };
  const value = normalizeLocationPayload(payload);
  return { valid: Boolean(value), value };
}

function normalizeRadius(value, { defaultValue, maximum }) {
  const candidate = value === undefined || value === null || value === '' ? defaultValue : finiteNumber(value);
  if (candidate === null || candidate <= 0 || candidate > maximum) return null;
  return candidate;
}

function normalizeMotion(payload) {
  const speed = payload?.speed_mps == null ? null : finiteNumber(payload.speed_mps);
  const heading = payload?.heading_deg == null ? null : finiteNumber(payload.heading_deg);
  if (speed !== null && (speed < 0 || speed > GEO_LIMITS.maxSpeedMetersPerSecond)) return null;
  if (heading !== null && (heading < 0 || heading > GEO_LIMITS.maxHeadingDegrees)) return null;
  return { speed_mps: speed, heading_deg: heading };
}

function normalizeLocationUpdate(payload) {
  const location = normalizeLocationPayload(payload);
  const motion = normalizeMotion(payload);
  return location && motion ? { ...location, ...motion } : null;
}

async function saveUserLocation(user, location) {
  await pool.query(
    `INSERT INTO user_locations (user_id, latitude, longitude, accuracy_m, captured_at, updated_at)
     VALUES ($1, $2, $3, $4, NOW(), NOW())
     ON CONFLICT (user_id) DO UPDATE SET latitude = EXCLUDED.latitude, longitude = EXCLUDED.longitude,
       accuracy_m = EXCLUDED.accuracy_m, captured_at = EXCLUDED.captured_at, updated_at = NOW()`,
    [user.id, location.latitude, location.longitude, location.accuracy_m]
  );
}

async function clearUserLocation(user) {
  await pool.query('DELETE FROM user_locations WHERE user_id = $1', [user.id]);
}

async function getSharedLocations() {
  const result = await pool.query(
    `SELECT u.username, u.role, l.latitude, l.longitude, l.accuracy_m, l.captured_at
     FROM user_locations l JOIN users u ON u.id = l.user_id
     WHERE u.is_active = TRUE ORDER BY u.username ASC`
  );
  return result.rows.map((row) => ({
    username: row.username,
    role: row.role,
    latitude: Number(row.latitude),
    longitude: Number(row.longitude),
    accuracy_m: row.accuracy_m == null ? null : Number(row.accuracy_m),
    captured_at: row.captured_at
  }));
}

function normalizeIncidentCode(value) {
  return typeof value === 'string' ? value.trim().slice(0, 32) : '';
}

async function createIncident(user, code, location) {
  const description = INCIDENT_CODE_MAP.get(code);
  const result = await pool.query(
    `INSERT INTO incident_events (code, description, username, user_id, latitude, longitude, accuracy_m)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id, code, description, username, latitude, longitude, accuracy_m, created_at`,
    [code, description, user.username, user.id, location?.latitude ?? null, location?.longitude ?? null, location?.accuracy_m ?? null]
  );
  return result.rows[0];
}

function activationTokenPayload(user, jti) {
  return { sub: String(user.id), username: user.username, jti, typ: 'device_activation' };
}

async function adminOnly(req, res, next) {
  try {
    const key = req.get('x-admin-api-key');
    if (!(await isAdminKeyValid(key))) return res.status(401).json({ error: 'Unauthorized' });
    return next();
  } catch (error) {
    return next(error);
  }
}

async function getActiveBoundUser(username, hardwareUuid) {
  const result = await pool.query(
    `SELECT id, username, role, hardware_uuid, is_active, session_version
     FROM users
     WHERE username = $1 AND is_active = TRUE AND hardware_uuid = $2`,
    [username, hardwareUuid]
  );
  return result.rowCount === 1 ? result.rows[0] : null;
}

function channelLockKey(channelId) {
  return `ptt:channel:${channelId}:lock`;
}

function makeLockValue(socket, user, channelId) {
  return JSON.stringify({ socket_id: socket.id, username: user.username, user_id: user.id, channel_id: channelId, started_at: new Date().toISOString() });
}

function parseLockValue(value) {
  try {
    return value ? JSON.parse(value) : null;
  } catch (_) {
    return null;
  }
}

async function releaseSocketTransmission(socket, channelId, reason = 'stopped', notify = true) {
  const user = socket.data.user;
  const lockValue = socket.data.transmissions?.get(channelId);
  if (!lockValue) return false;
  const released = await redis.eval(RELEASE_LOCK_SCRIPT, { keys: [channelLockKey(channelId)], arguments: [lockValue] });
  socket.data.transmissions.delete(channelId);
  if (notify && released === 1) {
    io.to(channelId).emit('ptt_stopped', { username: user.username, socket_id: socket.id, channel_id: channelId, reason });
  }
  return released === 1;
}

async function releaseAllSocketTransmissions(socket, reason = 'disconnected') {
  const channels = [...(socket.data.transmissions || new Map()).keys()];
  for (const channelId of channels) await releaseSocketTransmission(socket, channelId, reason, true);
}

async function disconnectUserSockets(user, reason, { killSwitch = false } = {}) {
  let disconnectedSockets = 0;
  for (const socket of io.sockets.sockets.values()) {
    if (String(socket.data.user?.id) !== String(user.id)) continue;
    await releaseAllSocketTransmissions(socket, reason);
    socket.emit('session_revoked', { reason, re_enrollment_required: true, kill_switch: killSwitch });
    socket.emit('account_disabled', { reason, kill_switch: killSwitch });
    socket.disconnect(true);
    disconnectedSockets += 1;
  }
  return disconnectedSockets;
}

async function disconnectRevokedSocket(socket, reason) {
  if (socket.data.revocationInProgress) return;
  socket.data.revocationInProgress = true;
  await releaseAllSocketTransmissions(socket, reason).catch(() => {});
  socket.emit('session_revoked', { reason, re_enrollment_required: true });
  socket.disconnect(true);
}

async function revokeSocketForLeader(socket, channelId) {
  const currentUser = socket.data.user;
  const currentLockValue = socket.data.transmissions?.get(channelId);
  if (!currentLockValue) return;
  await redis.eval(RELEASE_LOCK_SCRIPT, { keys: [channelLockKey(channelId)], arguments: [currentLockValue] });
  socket.data.transmissions.delete(channelId);
  socket.emit('ptt_muted_by_leader', {
    username: currentUser.username,
    channel_id: channelId,
    reason: 'ALFA override'
  });
}

function validatePttStartPayload(payload) {
  const username = normalizeUsername(payload?.username);
  const channelId = normalizeChannelId(payload?.channel_id);
  if (!username || !channelId) return null;
  return { username, channelId };
}

io.use(async (socket, next) => {
  try {
    const connectionQuota = await consumeQuota('socket:connect', socketClientAddress(socket), SOCKET_CONNECTION_LIMIT, SOCKET_EVENT_WINDOW_SECONDS);
    if (!connectionQuota.allowed) return next(new Error('Socket connection quota exceeded'));
    const username = normalizeUsername(socket.handshake.auth?.username);
    const hardwareUuid = normalizeHardwareUuid(socket.handshake.auth?.hardware_uuid);
    const session = readSessionToken(socket.handshake.auth?.session_token);
    if (!username || !hardwareUuid || !session) return next(new Error('authenticated username, device and session are required'));
    const authenticated = await resolveDeviceSession(session, { username, hardwareUuid });
    socket.data.user = authenticated.user;
    socket.data.claims = authenticated.claims;
    socket.data.sessionToken = session;
    socket.data.hardwareUuid = hardwareUuid;
    socket.data.transmissions = new Map();
    socket.data.lastEventAt = new Map();
    return next();
  } catch (error) {
    return next(new Error(error instanceof SessionValidationError ? 'Device session verification failed' : 'Authorization service unavailable'));
  }
});


async function getActiveTrackingSession(user) {
  const result = await pool.query('SELECT id FROM tracking_sessions WHERE user_id=$1 AND active=TRUE ORDER BY started_at DESC LIMIT 1', [user.id]);
  return result.rowCount ? result.rows[0] : null;
}
async function emitGeofenceEvents(user, location) {
  const fences = await pool.query('SELECT * FROM security_geofences WHERE active=TRUE');
  for (const fence of fences.rows) {
    const distance = distanceMeters(location.latitude, location.longitude, Number(fence.center_latitude), Number(fence.center_longitude));
    if (distance <= Number(fence.radius_m)) {
      io.to('location_viewers').emit('geofence_status', { username:user.username, geofence_id:fence.id, name:fence.name, inside:true, distance_m:Math.round(distance), captured_at:new Date().toISOString() });
    }
  }
}

io.on('connection', async (socket) => {
  socket.use(async ([eventName], next) => {
    try {
      const authenticated = await resolveDeviceSession(socket.data.sessionToken, { username: socket.data.user.username, hardwareUuid: socket.data.hardwareUuid });
      socket.data.user = authenticated.user;
      socket.data.claims = authenticated.claims;
      const policy = await enforceSocketEventPolicy(socket, eventName);
      if (!policy.allowed) {
        socket.emit('rate_limited', { event: eventName, reason: policy.reason, retry_after_seconds: policy.retryAfterSeconds || 1 });
        return next(new Error('Socket event rate limit exceeded'));
      }
      return next();
    } catch (error) {
      await disconnectRevokedSocket(socket, 'session revoked or authorization unavailable');
      return next(new Error('Device session is no longer valid'));
    }
  });
  const user = socket.data.user;
  socket.join(DEFAULT_CHANNEL_ID);
  const peers = [...io.sockets.sockets.values()]
    .filter((peer) => peer.id !== socket.id && peer.rooms.has(DEFAULT_CHANNEL_ID))
    .map((peer) => ({ socket_id: peer.id, username: peer.data.user?.username || 'operator' }));
  socket.emit('webrtc_peer_list', { channel_id: DEFAULT_CHANNEL_ID, peers });
  socket.to(DEFAULT_CHANNEL_ID).emit('webrtc_peer_joined', { socket_id: socket.id, username: user.username });
  if (user.username === 'ALFA' && user.role === 'leader') {
    socket.join('location_viewers');
    await getSharedLocations().then((locations) => socket.emit('location_snapshot', { locations, emitted_at: new Date().toISOString() })).catch((error) => console.error('Initial location snapshot failed:', error.message));
  }
  await setDeviceStatus(user, socket.data.hardwareUuid, 'online', false).catch((error) => console.error('Status update failed:', error.message));
  await getDashboardProfiles().then((profiles) => socket.emit('presence_snapshot', { profiles, emitted_at: new Date().toISOString() })).catch((error) => console.error('Initial presence snapshot failed:', error.message));
  await broadcastPresence();
  socket.emit('ptt_ready', { username: user.username, role: user.role, default_channel_id: DEFAULT_CHANNEL_ID });

  function relayWebRtc(eventName, payload) {
    const targetId = typeof payload?.target_socket_id === 'string' ? payload.target_socket_id.slice(0, 128) : '';
    const serialized = (() => { try { return JSON.stringify(payload); } catch (_) { return ''; } })();
    if (!targetId || targetId === socket.id || !io.sockets.sockets.has(targetId) || !serialized || Buffer.byteLength(serialized) > 12 * 1024) return;
    io.to(targetId).emit(eventName, { ...payload, from_socket_id: socket.id, from_username: socket.data.user.username });
  }
  socket.on('webrtc_offer', (payload) => relayWebRtc('webrtc_offer', payload));
  socket.on('webrtc_answer', (payload) => relayWebRtc('webrtc_answer', payload));
  socket.on('webrtc_ice_candidate', (payload) => relayWebRtc('webrtc_ice_candidate', payload));

  socket.on('location_update', async (payload, acknowledge) => {
    const reply = typeof acknowledge === 'function' ? acknowledge : () => {};
    const location = normalizeLocationUpdate(payload);
    if (!location) return reply({ ok: false, error: 'Valid latitude, longitude, accuracy, speed and heading values are required' });
    const currentUser = socket.data.user;
    try {
      await saveUserLocation(currentUser, location);
      const trackingSession = await getActiveTrackingSession(currentUser);
      if (trackingSession) {
        await pool.query('INSERT INTO location_history (tracking_session_id,user_id,username,latitude,longitude,accuracy_m,speed_mps,heading_deg) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [trackingSession.id, currentUser.id, currentUser.username, location.latitude, location.longitude, location.accuracy_m, location.speed_mps, location.heading_deg]);
        await emitGeofenceEvents(currentUser, location).catch((error) => console.error('Geofence event check failed:', error.message));
      }
      io.to('location_viewers').emit('location_update', {
        username: currentUser.username, role: currentUser.role, latitude: location.latitude, longitude: location.longitude, accuracy_m: location.accuracy_m, captured_at: new Date().toISOString()
      });
      reply({ ok: true });
    } catch (error) {
      console.error('Location update failed:', error.message);
      reply({ ok: false, error: 'Location update failed' });
    }
  });

  socket.on('location_stop', async (acknowledge) => {
    const reply = typeof acknowledge === 'function' ? acknowledge : () => {};
    try {
      await clearUserLocation(user);
      io.to('location_viewers').emit('location_removed', { username: user.username });
      reply({ ok: true });
    } catch (error) {
      console.error('Location removal failed:', error.message);
      reply({ ok: false, error: 'Location removal failed' });
    }
  });

  socket.on('incident_report', async (payload, acknowledge) => {
    const reply = typeof acknowledge === 'function' ? acknowledge : () => {};
    const code = normalizeIncidentCode(payload?.code);
    if (!INCIDENT_CODE_MAP.has(code)) return reply({ ok: false, error: 'Unknown incident code' });
    if (code === 'EVACUATION' && !(user.username === 'ALFA' && user.role === 'leader')) return reply({ ok: false, error: 'Only ALFA may issue the stadium evacuation code' });
    const parsedLocation = parseOptionalLocation(payload?.location);
    if (!parsedLocation.valid) return reply({ ok: false, error: 'Incident location must contain valid latitude, longitude and accuracy values' });
    const location = parsedLocation.value;
    try {
      const incident = await createIncident(user, code, location);
      await pool.query(
        `INSERT INTO security_incidents (incident_type, title, description, severity, status, source, reported_by, latitude, longitude, accuracy_m, metadata)
         VALUES ('incident', $1, $2, $3, 'open', 'incident_code', $4, $5, $6, $7, $8::jsonb)`,
        [code, incident.description, CRITICAL_INCIDENT_CODES.has(code) ? 'critical' : 'medium', user.username,
          location?.latitude ?? null, location?.longitude ?? null, location?.accuracy_m ?? null,
          JSON.stringify({ legacy_incident_id: incident.id })]
      );
      const incidentAlert = {
        id: incident.id, code: incident.code, description: incident.description,
        username: incident.username, latitude: incident.latitude == null ? null : Number(incident.latitude),
        longitude: incident.longitude == null ? null : Number(incident.longitude),
        accuracy_m: incident.accuracy_m == null ? null : Number(incident.accuracy_m), created_at: incident.created_at,
        critical: CRITICAL_INCIDENT_CODES.has(incident.code)
      };
      if (code === 'EVACUATION') {
        io.emit('evacuation_alert', { id: incidentAlert.id, code: incidentAlert.code, description: incidentAlert.description, username: incidentAlert.username, created_at: incidentAlert.created_at, critical: true });
      } else {
        io.to('location_viewers').emit('incident_alert', incidentAlert);
      }
      reply({ ok: true, incident_id: incident.id });
    } catch (error) {
      console.error('Incident report failed:', error.message);
      reply({ ok: false, error: 'Incident report failed' });
    }
  });

  socket.on('ptt_join', (payload, acknowledge) => {
    const channelId = normalizeChannelId(payload?.channel_id);
    if (!channelId) {
      if (typeof acknowledge === 'function') acknowledge({ ok: false, error: 'Valid channel_id is required' });
      return;
    }
    socket.join(channelId);
    if (typeof acknowledge === 'function') acknowledge({ ok: true, channel_id: channelId });
  });

  socket.on('ptt_start', async (payload, acknowledge) => {
    const parsed = validatePttStartPayload(payload);
    const reply = typeof acknowledge === 'function' ? acknowledge : () => {};
    if (!parsed || parsed.username !== user.username) {
      reply({ ok: false, error: 'username and channel_id are required and username must match the authorized device' });
      return;
    }
    try {
      const currentUser = await getActiveBoundUser(user.username, socket.data.hardwareUuid);
      if (!currentUser) {
        reply({ ok: false, error: 'Device binding is inactive or revoked' });
        socket.emit('account_disabled', { reason: 'kill switch or device revocation' });
        await releaseAllSocketTransmissions(socket, 'authorization_lost');
        socket.disconnect(true);
        return;
      }
      socket.data.user = currentUser;
      socket.join(parsed.channelId);
      const lockValue = makeLockValue(socket, currentUser, parsed.channelId);
      const isLeader = currentUser.username === 'ALFA' && currentUser.role === 'leader';
      const result = await redis.eval(isLeader ? LEADER_OVERRIDE_SCRIPT : LOCK_ACQUIRE_SCRIPT, {
        keys: [channelLockKey(parsed.channelId)],
        arguments: [lockValue, String(PTT_LOCK_TTL_SECONDS)]
      });
      const previousLock = parseLockValue(result?.[1]);
      if (!isLeader && Number(result?.[0]) !== 1) {
        reply({ ok: false, error: 'Channel is busy', active_username: previousLock?.username || null });
        socket.emit('ptt_denied', { channel_id: parsed.channelId, active_username: previousLock?.username || null });
        return;
      }

      if (isLeader && previousLock && previousLock.socket_id !== socket.id) {
        const previousSocket = io.sockets.sockets.get(previousLock.socket_id);
        if (previousSocket) await revokeSocketForLeader(previousSocket, parsed.channelId);
        io.to(parsed.channelId).emit('leader_transmitting', {
          username: 'ALFA',
          channel_id: parsed.channelId,
          interrupted_username: previousLock.username || null,
          override: true
        });
      }
      socket.data.transmissions.set(parsed.channelId, lockValue);
      io.to(parsed.channelId).emit('ptt_started', {
        username: currentUser.username,
        socket_id: socket.id,
        role: currentUser.role,
        channel_id: parsed.channelId,
        override: isLeader,
        started_at: new Date().toISOString()
      });
      await broadcastPresence();
      reply({ ok: true, channel_id: parsed.channelId, override: isLeader });
    } catch (error) {
      console.error('ptt_start error:', error.message);
      reply({ ok: false, error: 'PTT start failed' });
    }
  });

  socket.on('ptt_stop', async (payload, acknowledge) => {
    const channelId = normalizeChannelId(payload?.channel_id);
    const reply = typeof acknowledge === 'function' ? acknowledge : () => {};
    if (!channelId) {
      reply({ ok: false, error: 'Valid channel_id is required' });
      return;
    }
    try {
      const released = await releaseSocketTransmission(socket, channelId, 'stopped', true);
      await broadcastPresence();
      reply({ ok: released, channel_id: channelId, released });
    } catch (error) {
      console.error('ptt_stop error:', error.message);
      reply({ ok: false, error: 'PTT stop failed' });
    }
  });

  socket.on('disconnect', async () => {
    socket.to(DEFAULT_CHANNEL_ID).emit('webrtc_peer_left', { socket_id: socket.id, username: user.username });
    await releaseAllSocketTransmissions(socket, 'disconnected').catch((error) => console.error('PTT disconnect cleanup failed:', error.message));
    const stillBound = await getActiveBoundUser(user.username, socket.data.hardwareUuid).catch(() => null);
    if (stillBound) await setDeviceStatus(stillBound, null, 'offline', false).catch((error) => console.error('Offline status update failed:', error.message));
    await broadcastPresence();
  });
});

app.get('/health', async (req, res, next) => {
  try {
    await pool.query('SELECT 1');
    if (!redis.isReady) return res.status(503).json({ status: 'degraded', database: 'ok', redis: 'unavailable' });
    return res.json({ status: 'ok', database: 'ok', redis: 'ok', websocket: 'ok' });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/auth/verify-code', authLimiter, async (req, res) => {
  if (!(await accessCodeMatches(req.body?.access_code))) return res.status(401).json({ error: 'Invalid access code' });
  const gate = jwt.sign({ typ: 'access_gate' }, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: 600, issuer: JWT_ISSUER, audience: 'alpha-team-gate' });
  return res.json({ status: 'verified', gate_token: gate });
});

function verifyGate(token) {
  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'], issuer: JWT_ISSUER, audience: 'alpha-team-gate' });
}

app.post('/api/auth/enroll', authLimiter, async (req, res, next) => {
  const username = normalizeUsername(req.body?.username);
  const pin = typeof req.body?.pin === 'string' ? req.body.pin : '';
  const pinConfirmation = typeof req.body?.pin_confirmation === 'string' ? req.body.pin_confirmation : '';
  const hardwareUuid = normalizeHardwareUuid(req.body?.hardware_uuid);
  try {
    verifyGate(req.body?.gate_token);
    if (!PREDEFINED_USERNAMES.includes(username) || pin.length < 4 || pin.length > 64 || pin !== pinConfirmation || hardwareUuid.length < 8) return res.status(400).json({ error: 'Username, matching PIN and valid device identifier are required' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const userResult = await client.query('SELECT id, username, role, hardware_uuid, is_active, session_version FROM users WHERE username = $1 FOR UPDATE', [username]);
      if (userResult.rowCount !== 1) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Profile not found' }); }
      const user = userResult.rows[0];
      const credentialResult = await client.query('SELECT user_id FROM user_credentials WHERE user_id = $1', [user.id]);
      if (credentialResult.rowCount || user.hardware_uuid) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Username is already enrolled; ask ALFA for reset' }); }
      if (!user.is_active) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Account disabled' }); }
      const pinHash = await bcrypt.hash(pin, 12);
      const updated = await client.query('UPDATE users SET hardware_uuid = $1 WHERE id = $2 AND hardware_uuid IS NULL RETURNING id, username, role, hardware_uuid, is_active, session_version', [hardwareUuid, user.id]);
      await client.query('INSERT INTO user_credentials (user_id, pin_hash) VALUES ($1, $2)', [user.id, pinHash]);
      await writeAudit(client, 'self_enrolled', req, updated.rows[0], { hardware_uuid: hardwareUuid });
      await client.query('COMMIT');
      await setDeviceStatus(updated.rows[0], hardwareUuid, 'online', false);
      return res.status(201).json({ status: 'enrolled', username, role: user.role, session_token: sessionToken(updated.rows[0], hardwareUuid) });
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); if (error.code === '23505') return res.status(409).json({ error: 'Device identifier is already bound' }); return next(error); } finally { client.release(); }
  } catch (_) { return res.status(401).json({ error: 'Access verification expired' }); }
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  const username = normalizeUsername(req.body?.username);
  const pin = typeof req.body?.pin === 'string' ? req.body.pin : '';
  const hardwareUuid = normalizeHardwareUuid(req.body?.hardware_uuid);
  try {
    const result = await pool.query(`SELECT u.id, u.username, u.role, u.hardware_uuid, u.is_active, u.session_version, c.pin_hash FROM users u JOIN user_credentials c ON c.user_id = u.id WHERE u.username = $1`, [username]);
    if (result.rowCount !== 1 || !result.rows[0].is_active || !(await bcrypt.compare(pin, result.rows[0].pin_hash)) || result.rows[0].hardware_uuid !== hardwareUuid) return res.status(401).json({ error: 'Invalid username, PIN or device binding' });
    return res.json({ status: 'authenticated', username, role: result.rows[0].role, session_token: sessionToken(result.rows[0], hardwareUuid) });
  } catch (error) { return next(error); }
});

app.post('/api/leader/reset-member', sensitiveLimiter, verifySession, leaderOnly, async (req, res, next) => {
  const username = normalizeUsername(req.body?.username);
  if (!PREDEFINED_USERNAMES.includes(username) || username === 'ALFA') return res.status(400).json({ error: 'A resettable member username is required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const previous = await client.query('SELECT id, username, role, hardware_uuid FROM users WHERE username = $1 FOR UPDATE', [username]);
    if (previous.rowCount !== 1) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Profile not found' }); }
    const result = await client.query('UPDATE users SET hardware_uuid = NULL, is_active = TRUE, session_version = session_version + 1, updated_at = NOW() WHERE id = $1 RETURNING id, username, role, hardware_uuid, is_active, session_version', [previous.rows[0].id]);
    const member = result.rows[0];
    await client.query('DELETE FROM user_credentials WHERE user_id = $1', [member.id]);
    await client.query('DELETE FROM user_passkeys WHERE user_id = $1', [member.id]);
    await client.query('DELETE FROM push_subscriptions WHERE user_id = $1', [member.id]);
    await client.query('DELETE FROM activation_tokens WHERE user_id = $1 AND used_at IS NULL', [member.id]);
    await client.query('UPDATE tracking_sessions SET active = FALSE, stopped_at = NOW() WHERE user_id = $1 AND active = TRUE', [member.id]);
    await client.query('DELETE FROM user_locations WHERE user_id = $1', [member.id]);
    await writeAudit(client, 'leader_member_reset', req, member, { previous_hardware_uuid: previous.rows[0].hardware_uuid, session_version: member.session_version });
    await client.query('COMMIT');
    await Promise.all([
      redis.del(`webauthn:register:${member.username}`),
      redis.del(`webauthn:auth:${member.username}`),
      setDeviceStatus(member, null, 'offline', false)
    ]);
    const disconnectedSockets = await disconnectUserSockets(member, 'member reset by ALFA');
    await broadcastPresence();
    return res.json({ status: 'reset', username, revoked_session_version: member.session_version, disconnected_sockets: disconnectedSockets });
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); return next(error); } finally { client.release(); }
});

app.post('/api/admin/generate-activation', adminLimiter, adminOnly, async (req, res, next) => {
  const username = normalizeUsername(req.body?.username);
  if (!username) return res.status(400).json({ error: 'username is required' });
  if (!PREDEFINED_USERNAMES.includes(username)) return res.status(404).json({ error: 'Profile is not one of the predefined identities' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userResult = await client.query(`SELECT id, username, role, hardware_uuid, is_active FROM users WHERE username = $1 FOR UPDATE`, [username]);
    if (userResult.rowCount !== 1) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Profile is not one of the predefined identities' });
    }
    const user = userResult.rows[0];
    if (!user.is_active) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Profile is disabled by kill switch' });
    }
    if (user.hardware_uuid) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Profile is already device-bound' });
    }
    const jti = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + ACTIVATION_TTL_SECONDS * 1000);
    const token = jwt.sign(activationTokenPayload(user, jti), process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: ACTIVATION_TTL_SECONDS, issuer: JWT_ISSUER, audience: 'alpha-team-device' });
    await client.query(`INSERT INTO activation_tokens (jti, user_id, expires_at, issued_by) VALUES ($1, $2, $3, $4)`, [jti, user.id, expiresAt, 'admin-api']);
    await writeAudit(client, 'activation_issued', req, user, { jti, expires_at: expiresAt.toISOString() });
    await client.query('COMMIT');
    return res.status(201).json({ token, token_type: 'Bearer', expires_in: ACTIVATION_TTL_SECONDS, username: user.username, jti });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    return next(error);
  } finally {
    client.release();
  }
});

app.post('/api/device/activate', sensitiveLimiter, async (req, res, next) => {
  const token = typeof req.body?.token === 'string' ? req.body.token : '';
  const hardwareUuid = normalizeHardwareUuid(req.body?.hardware_uuid);
  if (!token || !hardwareUuid) return res.status(400).json({ error: 'token and hardware_uuid are required' });
  if (hardwareUuid.length < 8) return res.status(400).json({ error: 'hardware_uuid is too short' });
  let claims;
  try {
    claims = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'], issuer: JWT_ISSUER, audience: 'alpha-team-device' });
    if (claims.typ !== 'device_activation' || !claims.jti || !claims.sub) throw new Error('Invalid activation token type');
  } catch (_) {
    return res.status(401).json({ error: 'Invalid or expired activation token' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const tokenResult = await client.query(`SELECT id, jti, user_id, expires_at, used_at FROM activation_tokens WHERE jti = $1 FOR UPDATE`, [claims.jti]);
    if (tokenResult.rowCount !== 1 || tokenResult.rows[0].used_at || new Date(tokenResult.rows[0].expires_at) <= new Date()) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Activation token is invalid, expired, or already used' });
    }
    const userResult = await client.query(`SELECT id, username, role, hardware_uuid, is_active, session_version FROM users WHERE id = $1 AND username = $2 FOR UPDATE`, [claims.sub, claims.username]);
    if (userResult.rowCount !== 1) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Predefined profile not found' });
    }
    const user = userResult.rows[0];
    if (!user.is_active) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Account disabled by kill switch' });
    }
    if (user.hardware_uuid) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Profile is already bound to a device' });
    }
    const updateResult = await client.query(`UPDATE users SET hardware_uuid = $1, updated_at = NOW() WHERE id = $2 AND hardware_uuid IS NULL AND is_active = TRUE RETURNING id, username, role, hardware_uuid, is_active, session_version`, [hardwareUuid, user.id]);
    if (updateResult.rowCount !== 1) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Device binding race or account state change detected' });
    }
    const boundUser = updateResult.rows[0];
    await client.query('UPDATE activation_tokens SET used_at = NOW() WHERE id = $1 AND used_at IS NULL', [tokenResult.rows[0].id]);
    await writeAudit(client, 'device_activated', req, boundUser, { hardware_uuid: hardwareUuid, jti: claims.jti });
    await client.query('COMMIT');
    await setDeviceStatus(boundUser, hardwareUuid, 'online', false);
    return res.status(201).json({ status: 'activated', username: boundUser.username, role: boundUser.role, hardware_bound: true, session_token: sessionToken(boundUser, hardwareUuid) });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    if (error.code === '23505') return res.status(409).json({ error: 'hardware_uuid is already bound to another profile' });
    return next(error);
  } finally {
    client.release();
  }
});

app.post('/api/device/heartbeat', sensitiveLimiter, verifySession, async (req, res, next) => {
  const username = normalizeUsername(req.body?.username);
  const hardwareUuid = normalizeHardwareUuid(req.body?.hardware_uuid);
  if ((username && username !== req.sessionUser.username) || (hardwareUuid && hardwareUuid !== req.sessionUser.hardware_uuid)) return res.status(403).json({ error: 'Heartbeat identity does not match the authenticated device session' });
  try {
    await setDeviceStatus(req.sessionUser, req.sessionUser.hardware_uuid, 'online', false);
    await broadcastPresence();
    return res.json({ status: 'online', username: req.sessionUser.username, hardware_bound: true });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/admin/dashboard/status', adminLimiter, adminOnly, async (req, res, next) => {
  try {
    const profiles = await getDashboardProfiles();
    if (profiles.length !== PREDEFINED_USERNAMES.length) {
      return res.status(503).json({ error: 'Predefined profile set is incomplete', profile_count: profiles.length });
    }
    return res.json({
      generated_at: new Date().toISOString(),
      profile_count: profiles.length,
      profiles
    });
  } catch (error) {
    return next(error);
  }
});

app.post(['/api/admin/device/kill', '/api/admin/kill-switch'], adminLimiter, adminOnly, async (req, res, next) => {
  const username = normalizeUsername(req.body?.username);
  if (!username) return res.status(400).json({ error: 'username is required' });
  if (!PREDEFINED_USERNAMES.includes(username)) return res.status(404).json({ error: 'Profile is not one of the predefined identities' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const currentResult = await client.query(
      `SELECT id, username, role, hardware_uuid, is_active
       FROM users WHERE username = $1 FOR UPDATE`,
      [username]
    );
    if (currentResult.rowCount !== 1) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Profile not found' });
    }
    const previousUser = currentResult.rows[0];
    const result = await client.query(
      `UPDATE users
       SET is_active = FALSE, hardware_uuid = NULL, session_version = session_version + 1, updated_at = NOW()
       WHERE id = $1
       RETURNING id, username, role, hardware_uuid, is_active, session_version`,
      [previousUser.id]
    );
    const user = result.rows[0];
    await client.query('DELETE FROM activation_tokens WHERE user_id = $1 AND used_at IS NULL', [user.id]);
    await writeAudit(client, 'device_killed', req, user, {
      previous_hardware_uuid: previousUser.hardware_uuid,
      binding_reset: true
    });
    await client.query('COMMIT');

    await setDeviceStatus(user, null, 'offline', true);
    const disconnectedSockets = await disconnectUserSockets(user, 'remote device kill', { killSwitch: true });
    await broadcastPresence();
    return res.json({
      status: 'disabled',
      username: user.username,
      active: false,
      hardware_bound: false,
      device_uuid: null,
      disconnected_sockets: disconnectedSockets
    });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    return next(error);
  } finally {
    client.release();
  }
});

app.post('/api/admin/broadcast-alert', adminLimiter, adminOnly, async (req, res, next) => {
  const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
  if (!message) return res.status(400).json({ error: 'message is required' });
  if (message.length > 2048) return res.status(400).json({ error: 'message must not exceed 2048 characters' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const profileResult = await client.query('SELECT COUNT(*)::int AS count FROM users WHERE username = ANY($1::text[])', [PREDEFINED_USERNAMES]);
    const profileCount = profileResult.rows[0].count;
    if (profileCount !== 31) {
      await client.query('ROLLBACK');
      return res.status(503).json({ error: 'Predefined profile set is not complete', profile_count: profileCount });
    }
    const alertId = crypto.randomUUID();
    await writeAudit(client, 'emergency_broadcast', req, null, {
      alert_id: alertId,
      message_length: message.length,
      profile_count: profileCount
    });
    await client.query('COMMIT');
    const alert = {
      alert_id: alertId,
      message,
      severity: 'critical',
      issued_at: new Date().toISOString(),
      profile_count: profileCount
    };
    io.emit('emergency_broadcast_alert', alert);
    return res.status(202).json({
      status: 'broadcast',
      alert_id: alertId,
      profile_count: profileCount,
      connected_recipients: io.sockets.sockets.size
    });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    return next(error);
  } finally {
    client.release();
  }
});



// Security operations API: SOS, incident lifecycle, shifts, checkpoints, geofences and reports.
function securityLeaderOnly(req, res, next) {
  if (!req.sessionUser || req.sessionUser.username !== 'ALFA' || req.sessionUser.role !== 'leader') return res.status(403).json({ error: 'ALFA supervisor access is required' });
  return next();
}
function securityLocation(value) {
  const parsed = parseOptionalLocation(value);
  return parsed;
}
function securityPayload(req) {
  const parsedLocation = securityLocation(req.body?.location);
  return {
    title: typeof req.body?.title === 'string' ? req.body.title.trim().slice(0, 160) : '',
    description: typeof req.body?.description === 'string' ? req.body.description.trim().slice(0, 4000) : '',
    severity: ['low','medium','high','critical'].includes(req.body?.severity) ? req.body.severity : 'medium',
    location: parsedLocation.value,
    locationValid: parsedLocation.valid
  };
}
const SOS_ESCALATION_FIRST_SECONDS = Number.parseInt(process.env.SOS_ESCALATION_FIRST_SECONDS || '30', 10);
const SOS_ESCALATION_SECOND_SECONDS = Number.parseInt(process.env.SOS_ESCALATION_SECOND_SECONDS || '120', 10);
const WELLBEING_STALE_SECONDS = Number.parseInt(process.env.WELLBEING_STALE_SECONDS || '1800', 10);
async function getActiveEmergencyMode() {
  const result = await pool.query(`SELECT id,title,message,severity,active,activated_by,activated_at FROM emergency_modes WHERE active=TRUE ORDER BY activated_at DESC LIMIT 1`);
  return result.rows[0] || null;
}
async function notifySosEscalation(incident, level) {
  const message = level === 1 ? `SOS #${incident.id} δεν έχει επιβεβαιωθεί για ${SOS_ESCALATION_FIRST_SECONDS} δευτερόλεπτα.` : `SOS #${incident.id} παραμένει χωρίς επιβεβαίωση — απαιτείται άμεση ανάληψη.`;
  await pool.query(`INSERT INTO security_notifications (username,title,message,severity) SELECT username,$1,$2,'critical' FROM users WHERE username IN ('ALFA','Control')`, ['Κλιμάκωση SOS', message]);
  io.emit('security_sos_escalated', { incident_id: incident.id, username: incident.reported_by, title: incident.title, escalation_level: level, message, issued_at: new Date().toISOString() });
  io.emit('emergency_broadcast_alert', { alert_id: `sos-escalation-${incident.id}-${level}`, message, severity: 'critical', issued_at: new Date().toISOString() });
}
async function escalateOpenSos() {
  try {
    const first = await pool.query(`UPDATE security_incidents SET escalation_level=1, escalated_at=COALESCE(escalated_at,NOW()), last_escalation_at=NOW(), updated_at=NOW() WHERE incident_type IN ('sos','panic') AND status IN ('open','acknowledged','in_progress') AND acknowledged_at IS NULL AND escalation_level=0 AND created_at <= NOW() - ($1 || ' seconds')::INTERVAL RETURNING id,reported_by,title`, [String(Math.max(10, SOS_ESCALATION_FIRST_SECONDS))]);
    for (const incident of first.rows) await notifySosEscalation(incident, 1);
    const second = await pool.query(`UPDATE security_incidents SET escalation_level=2, last_escalation_at=NOW(), updated_at=NOW() WHERE incident_type IN ('sos','panic') AND status IN ('open','acknowledged','in_progress') AND acknowledged_at IS NULL AND escalation_level=1 AND created_at <= NOW() - ($1 || ' seconds')::INTERVAL AND (last_escalation_at IS NULL OR last_escalation_at <= NOW() - ($2 || ' seconds')::INTERVAL) RETURNING id,reported_by,title`, [String(Math.max(SOS_ESCALATION_SECOND_SECONDS, SOS_ESCALATION_FIRST_SECONDS + 10)), String(Math.max(30, SOS_ESCALATION_SECOND_SECONDS - SOS_ESCALATION_FIRST_SECONDS))]);
    for (const incident of second.rows) await notifySosEscalation(incident, 2);
  } catch (error) { console.error('SOS escalation check failed:', error.message); }
}
async function emitSecurityIncident(incident) {
  const payload = { ...incident, latitude: incident.latitude == null ? null : Number(incident.latitude), longitude: incident.longitude == null ? null : Number(incident.longitude), accuracy_m: incident.accuracy_m == null ? null : Number(incident.accuracy_m) };
  io.emit('security_incident_created', payload);
  if (payload.severity === 'critical' || payload.incident_type === 'sos' || payload.incident_type === 'panic') io.emit('emergency_broadcast_alert', { alert_id: `incident-${payload.id}`, message: `${payload.title} — ${payload.reported_by}`, severity: 'critical', issued_at: payload.created_at });
  return payload;
}

app.post('/api/security/sos', sensitiveLimiter, verifySession, async (req, res, next) => {
  const payload = securityPayload(req);
  if (!payload.locationValid) return res.status(400).json({ error: 'SOS location must contain valid latitude, longitude and accuracy values' });
  const title = payload.title || 'SOS — άμεση βοήθεια';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(`INSERT INTO security_incidents (incident_type,title,description,severity,status,source,reported_by,latitude,longitude,accuracy_m,metadata) VALUES ('sos',$1,$2,'critical','open','sos',$3,$4,$5,$6,$7::jsonb) RETURNING *`, [title, payload.description, req.sessionUser.username, payload.location?.latitude ?? null, payload.location?.longitude ?? null, payload.location?.accuracy_m ?? null, JSON.stringify({ silent: Boolean(req.body?.silent), device_uuid: req.sessionUser.hardware_uuid })]);
    await writeAudit(client, 'security_sos_created', req, req.sessionUser, { incident_id: result.rows[0].id, silent: Boolean(req.body?.silent) });
    await client.query('COMMIT');
    const incident = await emitSecurityIncident(result.rows[0]);
    return res.status(201).json({ ok: true, incident });
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); return next(error); } finally { client.release(); }
});

app.post('/api/security/sos/acknowledge', sensitiveLimiter, verifySession, securityLeaderOnly, async (req, res, next) => {
  const id = Number(req.body?.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Valid SOS incident id is required' });
  try {
    const result = await pool.query(`UPDATE security_incidents SET status='acknowledged', acknowledged_at=COALESCE(acknowledged_at,NOW()), first_response_at=COALESCE(first_response_at,NOW()), updated_at=NOW() WHERE id=$1 AND incident_type IN ('sos','panic') AND acknowledged_at IS NULL RETURNING *`, [id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Open SOS not found or already acknowledged' });
    await pool.query(`INSERT INTO audit_events (event_type,username,user_id,metadata) VALUES ($1,$2,$3,$4::jsonb)`, ['sos_acknowledged', req.sessionUser.username, req.sessionUser.id, JSON.stringify({ incident_id: id })]);
    io.emit('security_incident_updated', result.rows[0]);
    return res.json({ ok: true, incident: result.rows[0] });
  } catch (error) { return next(error); }
});

app.post('/api/security/wellbeing/checkin', sensitiveLimiter, verifySession, async (req, res, next) => {
  const parsedLocation = securityLocation(req.body?.location);
  if (!parsedLocation.valid) return res.status(400).json({ error: 'Check-in location must contain valid latitude, longitude and accuracy values' });
  const location = parsedLocation.value;
  try {
    const result = await pool.query(`INSERT INTO wellbeing_checkins (user_id,username,latitude,longitude,accuracy_m) VALUES ($1,$2,$3,$4,$5) RETURNING id,username,latitude,longitude,accuracy_m,created_at`, [req.sessionUser.id, req.sessionUser.username, location?.latitude ?? null, location?.longitude ?? null, location?.accuracy_m ?? null]);
    await pool.query(`INSERT INTO audit_events (event_type,username,user_id,metadata) VALUES ($1,$2,$3,$4::jsonb)`, ['wellbeing_checkin', req.sessionUser.username, req.sessionUser.id, JSON.stringify({ checkin_id: result.rows[0].id })]);
    io.to('location_viewers').emit('wellbeing_checkin', result.rows[0]);
    return res.status(201).json({ ok: true, checkin: result.rows[0] });
  } catch (error) { return next(error); }
});
app.post('/api/security/wellbeing/status', verifySession, securityLeaderOnly, async (req, res, next) => {
  try {
    const result = await pool.query(`SELECT u.username,u.role,c.created_at,c.latitude,c.longitude,c.accuracy_m FROM users u LEFT JOIN LATERAL (SELECT created_at,latitude,longitude,accuracy_m FROM wellbeing_checkins WHERE username=u.username ORDER BY created_at DESC LIMIT 1) c ON TRUE WHERE u.is_active=TRUE ORDER BY u.username`);
    const now = Date.now();
    return res.json({ users: result.rows.map((row) => ({ ...row, stale: !row.created_at || now - new Date(row.created_at).getTime() > WELLBEING_STALE_SECONDS * 1000 })), stale_after_seconds: WELLBEING_STALE_SECONDS });
  } catch (error) { return next(error); }
});

app.post('/api/security/emergency/status', verifySession, async (req, res, next) => { try { return res.json({ active: await getActiveEmergencyMode() }); } catch (error) { return next(error); } });
app.post('/api/security/emergency/activate', sensitiveLimiter, verifySession, securityLeaderOnly, async (req, res, next) => {
  const title = typeof req.body?.title === 'string' ? req.body.title.trim().slice(0, 160) : '';
  const message = typeof req.body?.message === 'string' ? req.body.message.trim().slice(0, 4000) : '';
  if (!title || !message) return res.status(400).json({ error: 'Emergency title and instructions are required' });
  try {
    const existing = await getActiveEmergencyMode();
    if (existing) return res.status(409).json({ error: 'An emergency mode is already active', active: existing });
    const result = await pool.query(`INSERT INTO emergency_modes (title,message,activated_by) VALUES ($1,$2,$3) RETURNING id,title,message,severity,active,activated_by,activated_at`, [title, message, req.sessionUser.username]);
    const mode = result.rows[0];
    await pool.query(`INSERT INTO audit_events (event_type,username,user_id,metadata) VALUES ($1,$2,$3,$4::jsonb)`, ['emergency_mode_activated', req.sessionUser.username, req.sessionUser.id, JSON.stringify({ emergency_id: mode.id })]);
    io.emit('emergency_mode', mode);
    return res.status(201).json({ ok: true, emergency: mode });
  } catch (error) { return next(error); }
});
app.post('/api/security/emergency/deactivate', sensitiveLimiter, verifySession, securityLeaderOnly, async (req, res, next) => {
  try {
    const result = await pool.query(`UPDATE emergency_modes SET active=FALSE,ended_at=NOW(),ended_by=$1 WHERE active=TRUE RETURNING id,title,ended_at,ended_by`, [req.sessionUser.username]);
    if (!result.rowCount) return res.status(404).json({ error: 'No active emergency mode' });
    await pool.query(`INSERT INTO audit_events (event_type,username,user_id,metadata) VALUES ($1,$2,$3,$4::jsonb)`, ['emergency_mode_deactivated', req.sessionUser.username, req.sessionUser.id, JSON.stringify({ emergency_id: result.rows[0].id })]);
    io.emit('emergency_mode_ended', result.rows[0]);
    return res.json({ ok: true, emergency: result.rows[0] });
  } catch (error) { return next(error); }
});

app.post('/api/security/incidents/create', sensitiveLimiter, verifySession, async (req, res, next) => {
  const payload = securityPayload(req);
  if (!payload.title) return res.status(400).json({ error: 'Incident title is required' });
  if (!payload.locationValid) return res.status(400).json({ error: 'Incident location must contain valid latitude, longitude and accuracy values' });
  try {
    const result = await pool.query(`INSERT INTO security_incidents (title,description,severity,reported_by,latitude,longitude,accuracy_m) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`, [payload.title, payload.description, payload.severity, req.sessionUser.username, payload.location?.latitude ?? null, payload.location?.longitude ?? null, payload.location?.accuracy_m ?? null]);
    const incident = await emitSecurityIncident(result.rows[0]);
    return res.status(201).json({ ok: true, incident });
  } catch (error) { return next(error); }
});

app.post('/api/security/incidents/list', verifySession, securityLeaderOnly, async (req, res, next) => {
  const status = ['','open','acknowledged','in_progress','resolved','cancelled'].includes(req.body?.status) ? req.body.status : '';
  const limit = parsePageLimit(req.body?.limit, 50, 100); const cursor = parseCursor(req.body?.cursor);
  try {
    const result = await pool.query(`SELECT id,incident_type,title,description,severity,status,source,reported_by,assigned_to,latitude,longitude,accuracy_m,metadata,created_at,updated_at,resolved_at,acknowledged_at,first_response_at,escalation_level,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_created_at FROM security_incidents WHERE ($1 = '' OR status = $1) AND ($2::timestamptz IS NULL OR (created_at,id) < ($2::timestamptz,$3::bigint)) ORDER BY created_at DESC,id DESC LIMIT $4`, [status, cursor?.created_at || null, cursor?.id || null, limit + 1]);
    const page = result.rows.slice(0, limit); const hasMore = result.rows.length > limit;
    const incidents = page.map(({ cursor_created_at: _cursorCreatedAt, ...incident }) => incident);
    return res.json({ incidents, next_cursor: hasMore ? encodeCursor(page[page.length - 1]) : null });
  } catch (error) { return next(error); }
});
app.post('/api/security/incidents/update', verifySession, securityLeaderOnly, async (req, res, next) => {
  const id = Number(req.body?.id); const status = req.body?.status; const assignedTo = typeof req.body?.assigned_to === 'string' && req.body.assigned_to ? req.body.assigned_to : null;
  if (!Number.isInteger(id) || !['open','acknowledged','in_progress','resolved','cancelled'].includes(status)) return res.status(400).json({ error: 'Valid incident id and status are required' });
  try {
    const result = await pool.query(`UPDATE security_incidents SET status=$1, assigned_to=COALESCE($2,assigned_to), updated_at=NOW(), resolved_at=CASE WHEN $1='resolved' THEN NOW() ELSE resolved_at END WHERE id=$3 RETURNING *`, [status, assignedTo, id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Incident not found' });
    await pool.query(`INSERT INTO security_notifications (username,title,message,severity) SELECT username,$1,$2,$3 FROM users WHERE username = $4`, ['Ενημέρωση συμβάντος', `Το συμβάν #${id} είναι πλέον ${status}.`, 'info', assignedTo || result.rows[0].reported_by]);
    io.emit('security_incident_updated', result.rows[0]);
    return res.json({ ok: true, incident: result.rows[0] });
  } catch (error) { return next(error); }
});

app.post('/api/security/shifts/list', verifySession, securityLeaderOnly, async (req, res, next) => {
  try { const result = await pool.query(`SELECT s.*, COALESCE(json_agg(json_build_object('username',m.username,'checked_in_at',m.checked_in_at,'checked_out_at',m.checked_out_at)) FILTER (WHERE m.username IS NOT NULL), '[]') AS members FROM security_shifts s LEFT JOIN security_shift_members m ON m.shift_id=s.id GROUP BY s.id ORDER BY s.starts_at DESC LIMIT 100`); return res.json({ shifts: result.rows }); } catch (error) { return next(error); }
});
app.post('/api/security/shifts/create', verifySession, securityLeaderOnly, async (req, res, next) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0,120) : ''; const site = typeof req.body?.site === 'string' ? req.body.site.trim().slice(0,160) : ''; const starts = new Date(req.body?.starts_at); const ends = new Date(req.body?.ends_at); const members = Array.isArray(req.body?.members) ? req.body.members.filter((x) => PREDEFINED_USERNAMES.includes(x)) : [];
  if (!name || Number.isNaN(starts.getTime()) || Number.isNaN(ends.getTime()) || ends <= starts) return res.status(400).json({ error: 'Name and valid shift times are required' });
  const client = await pool.connect(); try { await client.query('BEGIN'); const result = await client.query(`INSERT INTO security_shifts (name,site,starts_at,ends_at,supervisor,notes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`, [name,site,starts,ends,req.sessionUser.username,typeof req.body?.notes === 'string' ? req.body.notes.slice(0,2000) : '']); for (const member of members) await client.query('INSERT INTO security_shift_members (shift_id,username) VALUES ($1,$2) ON CONFLICT DO NOTHING',[result.rows[0].id,member]); await client.query('COMMIT'); return res.status(201).json({ ok:true, shift:result.rows[0], members }); } catch (error) { await client.query('ROLLBACK').catch(()=>{}); return next(error); } finally { client.release(); }
});
app.post('/api/security/shifts/check-in', verifySession, async (req, res, next) => { const shiftId = Number(req.body?.shift_id); if (!Number.isInteger(shiftId)) return res.status(400).json({error:'shift_id is required'}); try { const r=await pool.query(`UPDATE security_shift_members SET checked_in_at=NOW() WHERE shift_id=$1 AND username=$2 RETURNING *`,[shiftId,req.sessionUser.username]); if(!r.rowCount)return res.status(404).json({error:'Member is not assigned to this shift'}); return res.json({ok:true,member:r.rows[0]}); } catch(e){return next(e);} });

app.post('/api/security/checkpoints/list', verifySession, securityLeaderOnly, async (req, res, next) => { try { const r=await pool.query(`SELECT c.*, (SELECT json_agg(s ORDER BY s.scanned_at DESC) FROM (SELECT username,latitude,longitude,distance_m,scanned_at FROM security_checkpoint_scans WHERE checkpoint_id=c.id ORDER BY scanned_at DESC LIMIT 5) s) AS recent_scans FROM security_checkpoints c WHERE c.active=TRUE ORDER BY c.name`); return res.json({checkpoints:r.rows}); } catch(e){return next(e);} });
app.post('/api/security/checkpoints/create', sensitiveLimiter, verifySession, securityLeaderOnly, async (req, res, next) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 120) : '';
  const location = normalizeLocationPayload(req.body);
  const radius = normalizeRadius(req.body?.radius_m, { defaultValue: 75, maximum: GEO_LIMITS.maxCheckpointRadiusMeters });
  if (!name || !location || radius === null) return res.status(400).json({ error: 'Valid checkpoint name, GPS coordinates and radius are required' });
  try { const r = await pool.query(`INSERT INTO security_checkpoints (name,site,latitude,longitude,radius_m,created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`, [name, typeof req.body?.site === 'string' ? req.body.site.trim().slice(0, 160) : '', location.latitude, location.longitude, radius, req.sessionUser.username]); return res.status(201).json({ ok: true, checkpoint: r.rows[0] }); } catch (e) { return next(e); }
});
app.post('/api/security/checkpoints/scan', sensitiveLimiter, verifySession, async (req, res, next) => {
  const id = Number(req.body?.checkpoint_id); const location = normalizeLocationPayload(req.body);
  if (!Number.isInteger(id) || !location) return res.status(400).json({ error: 'checkpoint_id and valid GPS coordinates are required' });
  try { const c = await pool.query('SELECT * FROM security_checkpoints WHERE id=$1 AND active=TRUE', [id]); if (!c.rowCount) return res.status(404).json({ error: 'Checkpoint not found' }); const cp = c.rows[0]; const distance = distanceMeters(location.latitude, location.longitude, Number(cp.latitude), Number(cp.longitude)); if (distance > Number(cp.radius_m)) return res.status(422).json({ error: `Checkpoint is ${Math.round(distance)}m away`, distance_m: distance }); const r = await pool.query(`INSERT INTO security_checkpoint_scans (checkpoint_id,username,latitude,longitude,distance_m) VALUES ($1,$2,$3,$4,$5) RETURNING *`, [id, req.sessionUser.username, location.latitude, location.longitude, distance]); return res.json({ ok: true, valid: true, scan: r.rows[0] }); } catch (e) { return next(e); }
});
function distanceMeters(lat1,lon1,lat2,lon2){const R=6371000,toRad=(x)=>x*Math.PI/180,dLat=toRad(lat2-lat1),dLon=toRad(lon2-lon1);const a=Math.sin(dLat/2)**2+Math.cos(toRad(lat1))*Math.cos(toRad(lat2))*Math.sin(dLon/2)**2;return 2*R*Math.asin(Math.sqrt(a));}
app.post('/api/security/geofences/list', verifySession, securityLeaderOnly, async (req,res,next)=>{try{const r=await pool.query('SELECT * FROM security_geofences WHERE active=TRUE ORDER BY name');return res.json({geofences:r.rows});}catch(e){return next(e);}});
app.post('/api/security/geofences/create', sensitiveLimiter, verifySession, securityLeaderOnly, async (req, res, next) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 120) : '';
  const location = normalizeLocationPayload(req.body);
  const radius = normalizeRadius(req.body?.radius_m, { defaultValue: 250, maximum: GEO_LIMITS.maxGeofenceRadiusMeters });
  if (!name || !location || radius === null) return res.status(400).json({ error: 'Valid geofence name, GPS coordinates and radius are required' });
  try { const r = await pool.query(`INSERT INTO security_geofences (name,center_latitude,center_longitude,radius_m,created_by) VALUES ($1,$2,$3,$4,$5) RETURNING *`, [name, location.latitude, location.longitude, radius, req.sessionUser.username]); return res.status(201).json({ ok: true, geofence: r.rows[0] }); } catch (e) { return next(e); }
});
app.post('/api/security/geofences/check', sensitiveLimiter, verifySession, async (req, res, next) => {
  const location = normalizeLocationPayload(req.body);
  if (!location) return res.status(400).json({ error: 'Valid GPS coordinates are required' });
  try { const fences = await pool.query('SELECT * FROM security_geofences WHERE active=TRUE'); const states = []; for (const f of fences.rows) { const distance = distanceMeters(location.latitude, location.longitude, Number(f.center_latitude), Number(f.center_longitude)); states.push({ id: f.id, name: f.name, distance_m: Math.round(distance), inside: distance <= Number(f.radius_m) }); } return res.json({ geofences: states }); } catch (e) { return next(e); }
});
app.post('/api/security/report', verifySession, securityLeaderOnly, async (req,res,next)=>{try{const r=await pool.query(`SELECT COUNT(*) FILTER (WHERE created_at >= NOW()-INTERVAL '24 hours')::int AS incidents_24h, COUNT(*) FILTER (WHERE incident_type IN ('sos','panic') AND created_at >= NOW()-INTERVAL '30 days')::int AS sos_30d, COUNT(*) FILTER (WHERE status IN ('open','acknowledged','in_progress'))::int AS open_incidents, COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at-created_at))/60) FILTER (WHERE resolved_at IS NOT NULL),1),0) AS avg_resolution_minutes FROM security_incidents`);const scans=await pool.query(`SELECT COUNT(*)::int AS checkpoint_scans_24h FROM security_checkpoint_scans WHERE scanned_at>=NOW()-INTERVAL '24 hours'`);return res.json({summary:{...r.rows[0],...scans.rows[0]},generated_at:new Date().toISOString()});}catch(e){return next(e);}});
app.post('/api/security/report/detailed', verifySession, securityLeaderOnly, async (req,res,next)=>{try{const [summary,severity,status,recent,wellbeing]=await Promise.all([pool.query(`SELECT COUNT(*) FILTER (WHERE created_at>=NOW()-INTERVAL '24 hours')::int AS incidents_24h,COUNT(*) FILTER (WHERE incident_type IN ('sos','panic') AND created_at>=NOW()-INTERVAL '30 days')::int AS sos_30d,COUNT(*) FILTER (WHERE status IN ('open','acknowledged','in_progress'))::int AS open_incidents,COUNT(*) FILTER (WHERE escalation_level>0 AND created_at>=NOW()-INTERVAL '30 days')::int AS escalated_sos,COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (first_response_at-created_at))/60) FILTER (WHERE first_response_at IS NOT NULL),1),0) AS avg_first_response_minutes,COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at-created_at))/60) FILTER (WHERE resolved_at IS NOT NULL),1),0) AS avg_resolution_minutes FROM security_incidents`),pool.query(`SELECT severity,COUNT(*)::int AS total FROM security_incidents WHERE created_at>=NOW()-INTERVAL '30 days' GROUP BY severity ORDER BY severity`),pool.query(`SELECT status,COUNT(*)::int AS total FROM security_incidents WHERE created_at>=NOW()-INTERVAL '30 days' GROUP BY status ORDER BY status`),pool.query(`SELECT id,incident_type,title,severity,status,reported_by,assigned_to,created_at,acknowledged_at,resolved_at,escalation_level FROM security_incidents ORDER BY created_at DESC LIMIT 100`),pool.query(`SELECT COUNT(*) FILTER (WHERE c.created_at IS NULL OR c.created_at<NOW()-($1 || ' seconds')::INTERVAL)::int AS stale_users,COUNT(*) FILTER (WHERE c.created_at IS NOT NULL AND c.created_at>=NOW()-($1 || ' seconds')::INTERVAL)::int AS checked_in_users FROM users u LEFT JOIN LATERAL (SELECT created_at FROM wellbeing_checkins WHERE username=u.username ORDER BY created_at DESC LIMIT 1) c ON TRUE WHERE u.is_active=TRUE`,[String(WELLBEING_STALE_SECONDS)])]);return res.json({summary:{...summary.rows[0],wellbeing_stale_users:wellbeing.rows[0].stale_users,wellbeing_checked_in_users:wellbeing.rows[0].checked_in_users},by_severity:severity.rows,by_status:status.rows,recent_incidents:recent.rows,generated_at:new Date().toISOString()});}catch(e){return next(e);}});
app.post('/api/security/notifications', verifySession, async (req, res, next) => {
  const limit = parsePageLimit(req.body?.limit, 50, 100); const cursor = parseCursor(req.body?.cursor);
  try { const r = await pool.query(`SELECT *,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_created_at FROM security_notifications WHERE username=$1 AND ($2::timestamptz IS NULL OR (created_at,id) < ($2::timestamptz,$3::bigint)) ORDER BY created_at DESC,id DESC LIMIT $4`, [req.sessionUser.username, cursor?.created_at || null, cursor?.id || null, limit + 1]); const page = r.rows.slice(0, limit); const notifications = page.map(({ cursor_created_at: _cursorCreatedAt, ...notification }) => notification); return res.json({ notifications, next_cursor: r.rows.length > limit ? encodeCursor(page[page.length - 1]) : null }); } catch (e) { return next(e); }
});



// Phase 1: passkeys, web push subscription storage, and revocable device sessions.
app.post('/api/security/passkeys/register/options', verifySession, async (req, res, next) => {
  try {
    const existing = await pool.query('SELECT credential_id FROM user_passkeys WHERE user_id=$1', [req.sessionUser.id]);
    const options = await generateRegistrationOptions({ rpName: RP_NAME, rpID: RP_ID, userID: Buffer.from(String(req.sessionUser.id), 'utf8'), userName: req.sessionUser.username, userDisplayName: req.sessionUser.username, attestationType: 'none', excludeCredentials: existing.rows.map((r) => ({ id: Buffer.from(r.credential_id).toString('base64url') })), authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' }, timeout: 60000 });
    await redis.set(`webauthn:register:${req.sessionUser.username}`, JSON.stringify(options), { EX: 300 });
    return res.json(options);
  } catch (e) { return next(e); }
});
app.post('/api/security/passkeys/register/verify', verifySession, async (req, res, next) => {
  try {
    const raw = await redis.get(`webauthn:register:${req.sessionUser.username}`); if (!raw) return res.status(400).json({ error: 'Passkey registration challenge expired' });
    const verification = await verifyRegistrationResponse({ response: req.body?.response, expectedChallenge: JSON.parse(raw).challenge, expectedOrigin: EXPECTED_ORIGIN, expectedRPID: RP_ID, requireUserVerification: true });
    if (!verification.verified || !verification.registrationInfo) return res.status(400).json({ error: 'Passkey verification failed' });
    const info = verification.registrationInfo;
    await pool.query('INSERT INTO user_passkeys (user_id,credential_id,public_key,counter,transports) VALUES ($1,$2,$3,$4,$5::jsonb)', [req.sessionUser.id, Buffer.from(info.credential.id, 'base64url'), Buffer.from(info.credential.publicKey), info.credential.counter, JSON.stringify(info.credential.transports || [])]);
    await redis.del(`webauthn:register:${req.sessionUser.username}`); await pool.query('INSERT INTO audit_events (event_type,username,user_id,metadata) VALUES ($1,$2,$3,$4::jsonb)', ['passkey_registered', req.sessionUser.username, req.sessionUser.id, JSON.stringify({})]);
    return res.json({ ok: true });
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'This passkey is already registered' }); return next(e); }
});
app.post('/api/auth/passkey/options', async (req, res, next) => {
  const username = normalizeUsername(req.body?.username); try { const user = await pool.query('SELECT id,username FROM users WHERE username=$1 AND is_active=TRUE', [username]); if (!user.rowCount) return res.status(404).json({ error: 'Profile not found' }); const credentials = await pool.query('SELECT credential_id, transports FROM user_passkeys WHERE user_id=$1', [user.rows[0].id]); if (!credentials.rowCount) return res.status(404).json({ error: 'No passkey is registered for this profile' }); const options = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: 'required', allowCredentials: credentials.rows.map((c) => ({ id: Buffer.from(c.credential_id).toString('base64url'), transports: c.transports })) }); await redis.set(`webauthn:auth:${username}`, JSON.stringify({ challenge: options.challenge, user_id: user.rows[0].id }), { EX: 300 }); return res.json(options); } catch(e){return next(e);}
});
app.post('/api/auth/passkey/verify', async (req, res, next) => {
  const username=normalizeUsername(req.body?.username), hardwareUuid=normalizeHardwareUuid(req.body?.hardware_uuid); try { const pending=await redis.get(`webauthn:auth:${username}`); if(!pending)return res.status(400).json({error:'Passkey challenge expired'}); const p=JSON.parse(pending); const userResult=await pool.query('SELECT id,username,role,hardware_uuid,is_active,session_version FROM users WHERE id=$1 AND username=$2',[p.user_id,username]); if(!userResult.rowCount||!userResult.rows[0].is_active||userResult.rows[0].hardware_uuid!==hardwareUuid)return res.status(401).json({error:'Passkey device binding is invalid'}); const credentialId=Buffer.from(req.body?.response?.id||'','base64url'); const cr=await pool.query('SELECT public_key,counter,transports FROM user_passkeys WHERE user_id=$1 AND credential_id=$2',[p.user_id,credentialId]); if(!cr.rowCount)return res.status(401).json({error:'Unknown passkey'}); const c=cr.rows[0]; const verification=await verifyAuthenticationResponse({response:req.body.response,expectedChallenge:p.challenge,expectedOrigin:EXPECTED_ORIGIN,expectedRPID:RP_ID,credential:{id:credentialId.toString('base64url'),publicKey:Buffer.from(c.public_key),counter:Number(c.counter),transports:c.transports},requireUserVerification:true}); if(!verification.verified)return res.status(401).json({error:'Passkey authentication failed'}); await pool.query('UPDATE user_passkeys SET counter=$1,last_used_at=NOW() WHERE credential_id=$2',[verification.authenticationInfo.newCounter,credentialId]); await redis.del(`webauthn:auth:${username}`); return res.json({status:'authenticated',username,role:userResult.rows[0].role,session_token:sessionToken(userResult.rows[0],hardwareUuid)}); }catch(e){return next(e);}
});
app.post('/api/security/push/subscribe', verifySession, async (req,res,next)=>{const sub=req.body?.subscription;if(!sub?.endpoint||!sub?.keys?.p256dh||!sub?.keys?.auth)return res.status(400).json({error:'Valid push subscription is required'});try{await pool.query(`INSERT INTO push_subscriptions (user_id,endpoint,p256dh,auth) VALUES ($1,$2,$3,$4) ON CONFLICT(endpoint) DO UPDATE SET user_id=EXCLUDED.user_id,p256dh=EXCLUDED.p256dh,auth=EXCLUDED.auth,last_seen_at=NOW()`,[req.sessionUser.id,sub.endpoint,sub.keys.p256dh,sub.keys.auth]);return res.json({ok:true,delivery:'subscription_saved'});}catch(e){return next(e);}});
app.post('/api/security/device/revoke', sensitiveLimiter, verifySession, securityLeaderOnly, async (req, res, next) => {
  const username = normalizeUsername(req.body?.username);
  if (!PREDEFINED_USERNAMES.includes(username) || username === 'ALFA') return res.status(400).json({ error: 'Valid non-ALFA member username is required' });
  const client = await pool.connect();
  try { await client.query('BEGIN'); const r = await client.query('UPDATE users SET session_version=session_version+1,hardware_uuid=NULL,is_active=TRUE,updated_at=NOW() WHERE username=$1 RETURNING id,username,role,session_version', [username]); if (!r.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Profile not found' }); } const member = r.rows[0]; await client.query('DELETE FROM user_credentials WHERE user_id=$1', [member.id]); await client.query('DELETE FROM user_passkeys WHERE user_id=$1', [member.id]); await client.query('DELETE FROM push_subscriptions WHERE user_id=$1', [member.id]); await client.query('DELETE FROM user_locations WHERE user_id=$1', [member.id]); await client.query('UPDATE tracking_sessions SET active=FALSE,stopped_at=NOW() WHERE user_id=$1 AND active=TRUE', [member.id]); await writeAudit(client, 'device_revoked', req, member, { by: req.sessionUser.username, session_version: member.session_version }); await client.query('COMMIT'); await Promise.all([redis.del(`webauthn:register:${member.username}`), redis.del(`webauthn:auth:${member.username}`), setDeviceStatus(member, null, 'offline', false)]); const disconnectedSockets = await disconnectUserSockets(member, 'remote device revoke'); await broadcastPresence(); return res.json({ ok: true, username, revoked: true, disconnected_sockets: disconnectedSockets }); } catch (e) { await client.query('ROLLBACK').catch(() => {}); return next(e); } finally { client.release(); }
});
app.post('/api/security/device/logout', verifySession, async (req, res, next) => {
  try { const r = await pool.query('UPDATE users SET session_version=session_version+1,updated_at=NOW() WHERE id=$1 RETURNING id,username,role,hardware_uuid,is_active,session_version', [req.sessionUser.id]); const user = r.rows[0]; const disconnectedSockets = await disconnectUserSockets(user, 'secure logout'); return res.json({ ok: true, logged_out: true, disconnected_sockets: disconnectedSockets }); } catch (e) { return next(e); }
});



// Phase 2: explicit guard consent, live tracking sessions and route history.
app.post('/api/security/tracking/start', verifySession, async (req,res,next)=>{try{await pool.query('UPDATE tracking_sessions SET active=FALSE,stopped_at=NOW() WHERE user_id=$1 AND active=TRUE',[req.sessionUser.id]);const r=await pool.query(`INSERT INTO tracking_sessions (user_id,username,consent_text) VALUES ($1,$2,$3) RETURNING id,username,started_at,active,consent_text`,[req.sessionUser.id,req.sessionUser.username,typeof req.body?.consent_text==='string'?req.body.consent_text.slice(0,240):'User enabled live GPS tracking']);await pool.query(`INSERT INTO audit_events (event_type,username,user_id,metadata) VALUES ($1,$2,$3,$4::jsonb)`,['tracking_started',req.sessionUser.username,req.sessionUser.id,JSON.stringify({session_id:r.rows[0].id})]);io.to('location_viewers').emit('tracking_status',{username:req.sessionUser.username,active:true,started_at:r.rows[0].started_at});return res.json({ok:true,tracking:r.rows[0]});}catch(e){return next(e);}});
app.post('/api/security/tracking/stop', verifySession, async (req,res,next)=>{try{const r=await pool.query(`UPDATE tracking_sessions SET active=FALSE,stopped_at=NOW() WHERE user_id=$1 AND active=TRUE RETURNING id,username,started_at,stopped_at`,[req.sessionUser.id]);io.to('location_viewers').emit('tracking_status',{username:req.sessionUser.username,active:false,stopped_at:new Date().toISOString()});return res.json({ok:true,tracking:r.rows[0]||null});}catch(e){return next(e);}});
app.post('/api/security/tracking/status', verifySession, async (req,res,next)=>{try{const active=await getActiveTrackingSession(req.sessionUser);return res.json({active:Boolean(active),session:active});}catch(e){return next(e);}});
app.post('/api/security/tracking/sessions', verifySession, securityLeaderOnly, async (req,res,next)=>{try{const r=await pool.query(`SELECT DISTINCT ON (username) username,id,started_at,stopped_at,active,consent_text FROM tracking_sessions ORDER BY username,started_at DESC`);return res.json({sessions:r.rows});}catch(e){return next(e);}});
app.post('/api/security/tracking/history', verifySession, securityLeaderOnly, async (req, res, next) => {
  const username = normalizeUsername(req.body?.username); const hours = Math.min(Math.max(Number(req.body?.hours || 8), 1), 72); const limit = parsePageLimit(req.body?.limit, 1000, 2000); const cursor = parseCursor(req.body?.cursor);
  try { const r = await pool.query(`SELECT id,username,latitude,longitude,accuracy_m,speed_mps,heading_deg,captured_at,to_char(captured_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_created_at FROM location_history WHERE ($1='' OR username=$1) AND captured_at>=NOW()-($2 || ' hours')::INTERVAL AND ($3::timestamptz IS NULL OR (captured_at,id) > ($3::timestamptz,$4::bigint)) ORDER BY captured_at ASC,id ASC LIMIT $5`, [username, String(hours), cursor?.created_at || null, cursor?.id || null, limit + 1]); const page = r.rows.slice(0, limit); const points = page.map(({ cursor_created_at: _cursorCreatedAt, ...point }) => point); return res.json({ points, next_cursor: r.rows.length > limit ? encodeCursor(page[page.length - 1]) : null }); } catch (e) { return next(e); }
});


app.post('/api/security/device/attestation/status', verifySession, async (req,res,next)=>{try{const r=await pool.query('SELECT COUNT(*)::int AS passkeys FROM user_passkeys WHERE user_id=$1',[req.sessionUser.id]);return res.json({ok:true,web_attested:r.rows[0].passkeys>0,passkey_count:r.rows[0].passkeys,method:'WebAuthn passkey',note:'Platform attestation such as Play Integrity/App Attest is unavailable in a web-only deployment.'});}catch(e){return next(e);}});

function parseRedisInfoValue(info, key) {
  const match = new RegExp(`^${key}:(.+)$`, 'm').exec(info || '');
  return match ? Number(match[1]) || 0 : 0;
}

async function deleteRetentionBatch(table, timestampColumn, days) {
  const result = await pool.query(`WITH expired AS (SELECT ctid FROM ${table} WHERE ${timestampColumn} < NOW() - ($1 || ' days')::interval LIMIT $2) DELETE FROM ${table} WHERE ctid IN (SELECT ctid FROM expired) RETURNING 1`, [String(days), RETENTION_BATCH_SIZE]);
  return result.rowCount;
}

async function runRetentionCleanup() {
  const tasks = [
    ['activation_tokens', 'expires_at', RETENTION_DAYS.activation],
    ['audit_events', 'created_at', RETENTION_DAYS.audit],
    ['incident_events', 'created_at', RETENTION_DAYS.legacyIncidents],
    ['security_incidents', 'created_at', RETENTION_DAYS.incidents],
    ['location_history', 'captured_at', RETENTION_DAYS.locations],
    ['tracking_sessions', 'stopped_at', RETENTION_DAYS.locations],
    ['wellbeing_checkins', 'created_at', RETENTION_DAYS.wellbeing],
    ['security_notifications', 'created_at', RETENTION_DAYS.notifications],
    ['security_checkpoint_scans', 'scanned_at', RETENTION_DAYS.scans],
    ['security_geofence_events', 'created_at', RETENTION_DAYS.scans],
    ['push_subscriptions', 'last_seen_at', RETENTION_DAYS.subscriptions]
  ];
  const deleted = {};
  for (const [table, timestampColumn, days] of tasks) deleted[table] = await deleteRetentionBatch(table, timestampColumn, days);
  deleted.user_locations = await deleteRetentionBatch('user_locations', 'updated_at', 1);
  return { ran_at: new Date().toISOString(), deleted };
}

async function getStorageSnapshot() {
  const [database, tables, redisInfo, redisKeys] = await Promise.all([
    pool.query(`SELECT pg_database_size(current_database())::bigint AS bytes, pg_size_pretty(pg_database_size(current_database())) AS display`),
    pool.query(`SELECT relname AS table_name, pg_total_relation_size(relid)::bigint AS bytes FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 10`),
    redis.info('memory'),
    redis.dbSize()
  ]);
  const redisBytes = parseRedisInfoValue(redisInfo, 'used_memory');
  const databaseBytes = Number(database.rows[0]?.bytes || 0);
  const warnings = [];
  if (databaseBytes >= STORAGE_WARNING_BYTES) warnings.push('postgres_database_threshold_exceeded');
  if (redisBytes >= STORAGE_WARNING_BYTES) warnings.push('redis_memory_threshold_exceeded');
  return { generated_at: new Date().toISOString(), thresholds: { warning_bytes: STORAGE_WARNING_BYTES }, postgres: { bytes: databaseBytes, display: database.rows[0]?.display || null, largest_tables: tables.rows.map((row) => ({ table_name: row.table_name, bytes: Number(row.bytes) })) }, redis: { used_memory_bytes: redisBytes, keys: Number(redisKeys) }, warnings };
}

async function monitorStorage() {
  const snapshot = await getStorageSnapshot();
  if (snapshot.warnings.length) console.warn('Storage monitor warning:', JSON.stringify(snapshot));
  else console.info(`Storage monitor: postgres=${snapshot.postgres.bytes}B redis=${snapshot.redis.used_memory_bytes}B`);
  return snapshot;
}

app.get('/api/admin/storage', adminLimiter, adminOnly, async (req, res, next) => {
  try { return res.json(await getStorageSnapshot()); } catch (error) { return next(error); }
});
app.post('/api/admin/maintenance/retention', adminLimiter, adminOnly, async (req, res, next) => {
  try { const result = await runRetentionCleanup(); return res.json(result); } catch (error) { return next(error); }
});

app.use((error, req, res, next) => {
  console.error(`[${req.requestId || 'no-request-id'}]`, error.stack || error.message);
  if (res.headersSent) return next(error);
  return res.status(500).json({ error: 'Internal server error', request_id: req.requestId });
});

async function shutdown(signal) {
  console.log(`${signal}: shutting down`);
  if (global.sosEscalationTimer) clearInterval(global.sosEscalationTimer);
  if (global.retentionTimer) clearInterval(global.retentionTimer);
  if (global.storageMonitorTimer) clearInterval(global.storageMonitorTimer);
  await new Promise((resolve) => io.close(resolve));
  await redis.quit().catch(() => {});
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

async function initialize() {
  await redis.connect();
  await pool.query('SELECT 1');
  global.sosEscalationTimer = setInterval(escalateOpenSos, 15000);
  global.sosEscalationTimer.unref?.();
  await runRetentionCleanup().catch((error) => console.error('Initial retention cleanup failed:', error.message));
  await monitorStorage().catch((error) => console.error('Initial storage monitor failed:', error.message));
  global.retentionTimer = setInterval(() => runRetentionCleanup().catch((error) => console.error('Retention cleanup failed:', error.message)), RETENTION_INTERVAL_SECONDS * 1000);
  global.retentionTimer.unref?.();
  global.storageMonitorTimer = setInterval(() => monitorStorage().catch((error) => console.error('Storage monitor failed:', error.message)), STORAGE_MONITOR_INTERVAL_SECONDS * 1000);
  global.storageMonitorTimer.unref?.();
  httpServer.listen(PORT, '0.0.0.0', () => console.log(`Team Stadium backend listening on port ${PORT}`));
}

initialize().catch((error) => {
  console.error('Startup failure:', error.message);
  process.exit(1);
});
