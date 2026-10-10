/**
 * ContactMe WebSocket Relay Server
 *
 * Bridges the vPilot plugin (host) and the phone app (client) when they are
 * not on the same Wi-Fi network.
 *
 * Protocol:
 *   Plugin connects:  ws://HOST/ws?cid=1234567&role=host
 *   Phone connects:   ws://HOST/ws?cid=1234567&role=client
 *
 * Messages from host  → forwarded to ALL clients in the same session
 * Messages from client → forwarded to the host in the same session
 *
 * Deploy on Railway / Fly.io / Render — they handle TLS automatically
 * so the app and plugin use wss:// URLs.
 */

const { WebSocketServer } = require('ws');
const http = require('http');
const http2 = require('http2');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;

// ── APNs Live Activity relay config ──────────────────────────────────────────
// All secrets ride Railway env vars. `APNS_KEY_P8` is the PEM contents of
// the .p8 file (paste the full "-----BEGIN PRIVATE KEY-----..." blob).
// APNS_ENV: 'production' (App Store / TestFlight) or 'development' (local
// dev-signed builds). LA push tokens are environment-scoped — a prod
// key can't push to a dev-signed app and vice versa.
const APNS_KEY_P8    = (process.env.APNS_KEY_P8 || '').replace(/\\n/g, '\n');
const APNS_KEY_ID    = process.env.APNS_KEY_ID    || '';
const APNS_TEAM_ID   = process.env.APNS_TEAM_ID   || '';
const APNS_BUNDLE_ID = process.env.APNS_BUNDLE_ID || 'com.hutchens.contactme';
const APNS_ENV       = process.env.APNS_ENV       || 'production';
// Shared secret the plugin sends as a Bearer token. If unset, the
// endpoint is disabled — better to fail closed than accept anonymous
// requests to a resource that costs real quota + touches APNs.
const APNS_RELAY_TOKEN = process.env.APNS_RELAY_TOKEN || '';

// Boolean-coerce — using bare `&&` would return the last truthy VALUE
// (the secret token), which then got exposed via the /health endpoint's
// `apnsReady` field. Never let a config check hand you a credential.
const APNS_READY = Boolean(APNS_KEY_P8 && APNS_KEY_ID && APNS_TEAM_ID && APNS_RELAY_TOKEN);
if (!APNS_READY) {
  console.warn('[apns] Live Activity relay DISABLED — missing one of APNS_KEY_P8, APNS_KEY_ID, APNS_TEAM_ID, APNS_RELAY_TOKEN.');
}

// Pre-parse the private key once at boot so per-request signing is cheap.
let APNS_PRIVATE_KEY = null;
try {
  if (APNS_KEY_P8) {
    APNS_PRIVATE_KEY = crypto.createPrivateKey({ key: APNS_KEY_P8, format: 'pem' });
  }
} catch (e) {
  console.warn('[apns] Failed to parse APNS_KEY_P8:', e.message);
}

// JWT cache — regenerate every 30 min. APNs accepts JWTs up to 60 min
// old; halving it means slow clock drift never bumps us past the edge.
let JWT_CACHE = null;
let JWT_EXPIRES_MS = 0;
function apnsJwt() {
  if (JWT_CACHE && Date.now() < JWT_EXPIRES_MS) return JWT_CACHE;
  const iat = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: APNS_KEY_ID, typ: 'JWT' })).toString('base64url');
  const claims = Buffer.from(JSON.stringify({ iss: APNS_TEAM_ID, iat })).toString('base64url');
  const input  = `${header}.${claims}`;
  // dsaEncoding: 'ieee-p1363' produces r||s raw output — the format
  // APNs / JWT ES256 requires, not the DER default.
  const sig = crypto.sign('SHA256', Buffer.from(input), { key: APNS_PRIVATE_KEY, dsaEncoding: 'ieee-p1363' });
  JWT_CACHE = `${input}.${sig.toString('base64url')}`;
  JWT_EXPIRES_MS = Date.now() + 30 * 60 * 1000;
  return JWT_CACHE;
}

/**
 * POST a Live Activity update to Apple's push service. Returns
 * { status, body } — the status is APNs's :status pseudo-header, and
 * body is Apple's JSON-encoded error reason (empty on 200 success).
 */
function apnsSendLiveActivity({ token, contentState, event, dismissAfterSeconds }) {
  return new Promise((resolve, reject) => {
    const host = APNS_ENV === 'development' ? 'api.sandbox.push.apple.com' : 'api.push.apple.com';
    const client = http2.connect(`https://${host}`);
    // Guard against socket errors that fire before the request is sent.
    client.on('error', (err) => reject(err));
    const req = client.request({
      ':method': 'POST',
      ':path':   `/3/device/${token}`,
      'apns-topic':     `${APNS_BUNDLE_ID}.push-type.liveactivity`,
      'apns-push-type': 'liveactivity',
      'apns-priority':  '10',
      'authorization':  `bearer ${apnsJwt()}`,
      'content-type':   'application/json',
    });
    const payload = {
      aps: {
        timestamp: Math.floor(Date.now() / 1000),
        event,
        'content-state': contentState,
        ...(dismissAfterSeconds != null
          ? { 'dismissal-date': Math.floor(Date.now() / 1000) + dismissAfterSeconds }
          : {}),
      },
    };
    let status = 0;
    let body = '';
    req.setEncoding('utf8');
    req.on('response', (headers) => { status = headers[':status']; });
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => { client.close(); resolve({ status, body }); });
    req.on('error', (err) => { client.close(); reject(err); });
    req.end(JSON.stringify(payload));
  });
}

// Read a JSON body up to some sane limit — the LA payloads are tiny.
function readJsonBody(req, maxBytes = 8 * 1024) {
  return new Promise((resolve, reject) => {
    let received = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      received += chunk.length;
      if (received > maxBytes) {
        req.destroy();
        return reject(new Error('body too large'));
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const buf = Buffer.concat(chunks);
      if (!buf.length) return resolve({});
      try { resolve(JSON.parse(buf.toString('utf8'))); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

// ── HTTP server (health + APNs relay) ────────────────────────────────────────
const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      sessions: sessions.size,
      uptime: Math.floor(process.uptime()),
      apnsReady: APNS_READY,
    }));
    return;
  }

  // POST /apns/live-activity — plugin's Live Activity update relay.
  // Auth: Authorization: Bearer <APNS_RELAY_TOKEN>. Body shape:
  //   { token, arrival, distanceNm, etaMinutes, event? }
  // event defaults to "update"; pass "end" to dismiss the activity.
  if (req.method === 'POST' && req.url === '/apns/live-activity') {
    if (!APNS_READY) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'apns_relay_disabled' }));
      return;
    }
    // Bearer auth
    const auth = req.headers['authorization'] || '';
    const supplied = auth.replace(/^bearer\s+/i, '').trim();
    if (!supplied || supplied !== APNS_RELAY_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'unauthorized' }));
      return;
    }
    let body;
    try { body = await readJsonBody(req); }
    catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'bad_body', detail: e.message }));
      return;
    }
    const token = String(body.token || '').trim();
    if (!token) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'missing_token' }));
      return;
    }
    const event = body.event === 'end' ? 'end' : 'update';
    // -1 sentinel matches the SwiftUI struct's "unknown" convention.
    // displayMode: 0 = compact pill shows distance, 1 = shows ETA. Plugin
    // alternates on each push so the pill cycles at the push cadence.
    const contentState = {
      distanceNm: Number.isFinite(+body.distanceNm) ? +body.distanceNm : -1,
      etaMinutes: Number.isFinite(+body.etaMinutes) ? +body.etaMinutes : -1,
      displayMode: Number.isFinite(+body.displayMode) ? (+body.displayMode) & 1 : 0,
    };
    const dismissAfterSeconds = event === 'end' ? 0 : null;
    try {
      const result = await apnsSendLiveActivity({ token, contentState, event, dismissAfterSeconds });
      const ok = result.status === 200;
      res.writeHead(ok ? 200 : 502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok, apns: result }));
      if (!ok) log(`APNs push ${result.status}: ${result.body.slice(0, 200)}`);
    } catch (e) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'apns_send_failed', detail: e.message }));
      log(`APNs push exception: ${e.message}`);
    }
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('ContactMe Relay Server\n');
});

// ── Session store ─────────────────────────────────────────────────────────────
// sessions: Map<cid, {
//   host: WebSocket | null,
//   clients: Set<WebSocket>,
//   // Buffered registration frames so a late-joining host (plugin) still
//   // gets the phone's push token when the phone connected first. Each
//   // slot holds the raw frame string that the phone sent, keyed by type,
//   // so a reconnect with a fresh token overwrites the old value. Replay
//   // happens on host-connect; frames are plain strings (not Buffers).
//   buffered: {
//     register_push_token: string | null,
//     register_arrival_activity_android: string | null,
//     register_arrival_activity_token: string | null,
//   },
// }>
const sessions = new Map();

// Message types to stash. These are small, idempotent registrations the
// plugin needs on startup — never commands or user traffic.
const BUFFERED_TYPES = new Set([
  'register_push_token',
  'register_arrival_activity_android',
  'register_arrival_activity_token',
]);

function getOrCreateSession(cid) {
  if (!sessions.has(cid)) {
    sessions.set(cid, {
      host: null,
      clients: new Set(),
      buffered: {
        register_push_token: null,
        register_arrival_activity_android: null,
        register_arrival_activity_token: null,
      },
    });
  }
  return sessions.get(cid);
}

// Parse a client→host frame to keep the registration buffer in sync.
// A registration frame is stashed for later replay; an unregister frame
// clears the corresponding slot so a plugin reconnect after a flight
// doesn't resurrect a stale Live Activity push loop. Non-text frames and
// un-parseable JSON are ignored (passthrough only).
function maybeBuffer(session, data, isBinary) {
  if (isBinary) return;
  let text;
  try {
    text = typeof data === 'string' ? data : data.toString('utf8');
  } catch { return; }
  if (!text || text[0] !== '{') return;
  let parsed;
  try { parsed = JSON.parse(text); } catch { return; }
  const type = parsed && parsed.type;
  if (!type) return;
  if (BUFFERED_TYPES.has(type)) {
    session.buffered[type] = text;
    return;
  }
  // Clear both activity slots when the phone ends its Live Activity. The
  // phone sends one unregister for either platform, so wipe both. Without
  // this, Railway's ~60s idle-close triggers a plugin reconnect, replay
  // fires the cached register_arrival_activity_*, and the plugin resumes
  // pushing updates to an activity the phone has long since ended.
  if (type === 'unregister_arrival_activity_token') {
    session.buffered.register_arrival_activity_token = null;
    session.buffered.register_arrival_activity_android = null;
  }
}

// Replay stashed registrations to a freshly connected host. Order
// doesn't matter — each is self-contained — but we send push_token
// first so a plugin that logs on connect has the common case ready.
function replayBuffered(session) {
  const host = session.host;
  if (!host || host.readyState !== 1) return;
  const order = [
    'register_push_token',
    'register_arrival_activity_android',
    'register_arrival_activity_token',
  ];
  for (const key of order) {
    const frame = session.buffered[key];
    if (frame) host.send(frame);
  }
}

function cleanupSession(cid) {
  const session = sessions.get(cid);
  if (!session) return;
  if (session.host === null && session.clients.size === 0) {
    sessions.delete(cid);
    log(`session ${cid} closed`);
  }
}

// ── WebSocket server ──────────────────────────────────────────────────────────
const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

wss.on('connection', (ws, req) => {
  // Parse query params — req.url is relative, so prepend a dummy base
  let cid, role;
  try {
    const parsed = new URL(req.url, 'http://x');
    cid  = parsed.searchParams.get('cid')?.trim();
    role = parsed.searchParams.get('role')?.trim();
  } catch {
    ws.close(4000, 'Bad URL');
    return;
  }

  if (!cid) {
    ws.close(4001, 'Missing cid');
    return;
  }
  if (role !== 'host' && role !== 'client') {
    ws.close(4002, 'role must be host or client');
    return;
  }

  const session = getOrCreateSession(cid);
  log(`${role} connected   cid=${cid}`);

  // ── HOST ──────────────────────────────────────────────────────────────────
  if (role === 'host') {
    // Replace an existing host (reconnect after network hiccup)
    if (session.host && session.host.readyState === /* OPEN */ 1) {
      log(`replacing existing host cid=${cid}`);
      session.host.close(1001, 'Replaced by new host connection');
    }
    session.host = ws;

    // Replay any registrations the phone sent while the host was offline.
    // Without this, an xPilot plugin that cold-starts after the phone has
    // already connected never receives the push token and silently sits
    // without push capability for the rest of the flight.
    replayBuffered(session);

    ws.on('message', (data, isBinary) => {
      // Forward every host message to all phone clients, preserving frame type
      session.clients.forEach((client) => {
        if (client.readyState === 1) client.send(data, { binary: isBinary });
      });
    });

    ws.on('close', () => {
      if (session.host === ws) session.host = null;
      cleanupSession(cid);
      log(`host disconnected cid=${cid}`);
    });

    ws.on('error', (err) => {
      log(`host error cid=${cid}: ${err.message}`);
    });

  // ── CLIENT (PHONE) ────────────────────────────────────────────────────────
  } else {
    session.clients.add(ws);

    ws.on('message', (data, isBinary) => {
      // Snapshot registrations so a later host-connect can replay them.
      // Done BEFORE forwarding so even if the host is online right now,
      // the latest token is cached for a future reconnect.
      maybeBuffer(session, data, isBinary);

      // Forward every client message to the host (plugin), preserving frame type
      if (session.host && session.host.readyState === 1) {
        session.host.send(data, { binary: isBinary });
      }
    });

    ws.on('close', () => {
      session.clients.delete(ws);
      cleanupSession(cid);
      log(`client disconnected cid=${cid}`);
    });

    ws.on('error', (err) => {
      log(`client error cid=${cid}: ${err.message}`);
    });
  }
});

// ── Heartbeat — drops zombie connections every 30 s ──────────────────────────
const PING_INTERVAL = 30_000;
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws['_alive'] === false) {
      ws.terminate();
      return;
    }
    ws['_alive'] = false;
    ws.ping();
  });
}, PING_INTERVAL);

wss.on('connection', (ws) => {
  ws['_alive'] = true;
  ws.on('pong', () => { ws['_alive'] = true; });
});

// ── Start ─────────────────────────────────────────────────────────────────────
httpServer.listen(PORT, () => {
  log(`relay server listening on port ${PORT}`);
});

function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}
