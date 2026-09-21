require('dotenv').config();

const crypto = require('crypto');
const http = require('http');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const Redis = require('ioredis');


const { Server } = require('socket.io');

const requiredEnvironment = ['DATABASE_URL', 'REDIS_URL', 'JWT_SECRET', 'ADMIN_API_KEY'];
for (const key of requiredEnvironment) {
  if (!process.env[key]) throw new Error(`Missing required environment variable: ${key}`);
}
if (process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters long');
if (process.env.ADMIN_API_KEY.length < 24) throw new Error('ADMIN_API_KEY must be at least 24 characters long');

const PORT = Number.parseInt(process.env.PORT || '3000', 10);
const ACTIVATION_TTL_SECONDS = Number.parseInt(process.env.ACTIVATION_TTL_SECONDS || '600', 10);
const STATUS_TTL_SECONDS = Number.parseInt(process.env.REDIS_STATUS_TTL_SECONDS || '120', 10);
const PTT_LOCK_TTL_SECONDS = Number.parseInt(process.env.PTT_LOCK_TTL_SECONDS || '30', 10);
const JWT_ISSUER = process.env.JWT_ISSUER || 'alpha-team-ptt';
const DEFAULT_CHANNEL_ID = 'alpha-team';
const PREDEFINED_USERNAMES = Object.freeze([
  'ALFA', 'Bravo', 'Charlie', 'Delta', 'Echo', 'Foxtrot', 'Golf', 'Hotel', 'India', 'Juliet',
  'Kilo', 'Lima', 'Mike', 'November', 'Oscar', 'Papa', 'Romeo', 'Quadec', 'Sierra', 'Tango',
  'Uniform', 'Victor', 'Whisky', 'X-ray', 'Yankee', 'Zulu', 'Sentinel', 'Patrol', 'Response',
  'Guardian', 'Control'
]);
const app = express();
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map((value) => value.trim()) : false,
    methods: ['GET', 'POST']
  },
  transports: ['websocket', 'polling'],
  maxHttpBufferSize: 16 * 1024
});
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));
app.use(express.static('public'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: true } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});


const redis = new Redis(process.env.REDIS_URL + "?tls=true");


redis.on('error', (error) => console.error('Redis error:', error.message));
console.log("Redis client initialized");

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
    `SELECT id, username, role, hardware_uuid, is_active
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
    io.to(channelId).emit('ptt_stopped', { username: user.username, channel_id: channelId, reason });
  }
  return released === 1;
}

async function releaseAllSocketTransmissions(socket, reason = 'disconnected') {
  const channels = [...(socket.data.transmissions || new Map()).keys()];
  for (const channelId of channels) await releaseSocketTransmission(socket, channelId, reason, true);
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
    const username = normalizeUsername(socket.handshake.auth?.username);
    const hardwareUuid = normalizeHardwareUuid(socket.handshake.auth?.hardware_uuid);
    if (!username || !hardwareUuid) return next(new Error('username and hardware_uuid are required'));
    const user = await getActiveBoundUser(username, hardwareUuid);
    if (!user) return next(new Error('Active device binding verification failed'));
    socket.data.user = user;
    socket.data.hardwareUuid = hardwareUuid;
    socket.data.transmissions = new Map();
    return next();
  } catch (error) {
    return next(new Error('Authorization service unavailable'));
  }
});

io.on('connection', async (socket) => {
  const user = socket.data.user;
  socket.join(DEFAULT_CHANNEL_ID);
  await setDeviceStatus(user, socket.data.hardwareUuid, 'online', false).catch((error) => console.error('Status update failed:', error.message));
  await getDashboardProfiles().then((profiles) => socket.emit('presence_snapshot', { profiles, emitted_at: new Date().toISOString() })).catch((error) => console.error('Initial presence snapshot failed:', error.message));
  await broadcastPresence();
  socket.emit('ptt_ready', { username: user.username, role: user.role, default_channel_id: DEFAULT_CHANNEL_ID });

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
    await releaseAllSocketTransmissions(socket, 'disconnected').catch((error) => console.error('PTT disconnect cleanup failed:', error.message));
    await setDeviceStatus(user, null, 'offline', false).catch((error) => console.error('Offline status update failed:', error.message));
    await broadcastPresence();
  });
});

app.use((req, res, next) => {
  req.requestId = requestId();
  res.setHeader('x-request-id', req.requestId);
  next();
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

app.post('/api/admin/generate-activation', adminOnly, async (req, res, next) => {
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

app.post('/api/device/activate', async (req, res, next) => {
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
    const userResult = await client.query(`SELECT id, username, role, hardware_uuid, is_active FROM users WHERE id = $1 AND username = $2 FOR UPDATE`, [claims.sub, claims.username]);
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
    const updateResult = await client.query(`UPDATE users SET hardware_uuid = $1, updated_at = NOW() WHERE id = $2 AND hardware_uuid IS NULL AND is_active = TRUE RETURNING id, username, role, hardware_uuid, is_active`, [hardwareUuid, user.id]);
    if (updateResult.rowCount !== 1) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Device binding race or account state change detected' });
    }
    const boundUser = updateResult.rows[0];
    await client.query('UPDATE activation_tokens SET used_at = NOW() WHERE id = $1 AND used_at IS NULL', [tokenResult.rows[0].id]);
    await writeAudit(client, 'device_activated', req, boundUser, { hardware_uuid: hardwareUuid, jti: claims.jti });
    await client.query('COMMIT');
    await setDeviceStatus(boundUser, hardwareUuid, 'online', false);
    return res.status(201).json({ status: 'activated', username: boundUser.username, role: boundUser.role, hardware_bound: true });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    if (error.code === '23505') return res.status(409).json({ error: 'hardware_uuid is already bound to another profile' });
    return next(error);
  } finally {
    client.release();
  }
});

app.post('/api/device/heartbeat', async (req, res, next) => {
  const username = normalizeUsername(req.body?.username);
  const hardwareUuid = normalizeHardwareUuid(req.body?.hardware_uuid);
  if (!username || !hardwareUuid) return res.status(400).json({ error: 'username and hardware_uuid are required' });
  try {
    const user = await getActiveBoundUser(username, hardwareUuid);
    if (!user) {
      const disabled = await pool.query('SELECT id, username, role, hardware_uuid, is_active FROM users WHERE username = $1', [username]);
      if (disabled.rowCount === 1 && !disabled.rows[0].is_active) await setDeviceStatus(disabled.rows[0], null, 'offline', true);
      return res.status(403).json({ error: 'Device binding verification failed or account disabled' });
    }
    await setDeviceStatus(user, hardwareUuid, 'online', false);
    await broadcastPresence();
    return res.json({ status: 'online', username: user.username, hardware_bound: true });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/admin/dashboard/status', adminOnly, async (req, res, next) => {
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

app.post(['/api/admin/device/kill', '/api/admin/kill-switch'], adminOnly, async (req, res, next) => {
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
       SET is_active = FALSE, hardware_uuid = NULL, updated_at = NOW()
       WHERE id = $1
       RETURNING id, username, role, hardware_uuid, is_active`,
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
    let disconnectedSockets = 0;
    for (const socket of io.sockets.sockets.values()) {
      if (socket.data.user?.username === user.username) {
        await releaseAllSocketTransmissions(socket, 'remote_wipe');
        socket.emit('account_disabled', { reason: 'remote device kill' });
        socket.disconnect(true);
        disconnectedSockets += 1;
      }
    }
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

app.post('/api/admin/broadcast-alert', adminOnly, async (req, res, next) => {
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

app.use((error, req, res, next) => {
  console.error(`[${req.requestId || 'no-request-id'}]`, error.stack || error.message);
  if (res.headersSent) return next(error);
  return res.status(500).json({ error: 'Internal server error', request_id: req.requestId });
});

async function shutdown(signal) {
  console.log(`${signal}: shutting down`);
  await new Promise((resolve) => io.close(resolve));
  await redis.quit().catch(() => {});
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

async function initialize() {
  await pool.query('SELECT 1');
  httpServer.listen(PORT, '0.0.0.0', () => console.log(`Alpha Team PTT backend listening on port ${PORT}`));
}

initialize().catch((error) => {
  console.error('Startup failure:', error.message);
  process.exit(1);
});
