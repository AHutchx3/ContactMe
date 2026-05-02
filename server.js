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
const { URL } = require('url');

const PORT = process.env.PORT || 3000;

// ── HTTP server (health-check endpoint) ──────────────────────────────────────
const httpServer = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      sessions: sessions.size,
      uptime: Math.floor(process.uptime()),
    }));
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('ContactMe Relay Server\n');
});

// ── Session store ─────────────────────────────────────────────────────────────
// sessions: Map<cid, { host: WebSocket | null, clients: Set<WebSocket> }>
const sessions = new Map();

function getOrCreateSession(cid) {
  if (!sessions.has(cid)) {
    sessions.set(cid, { host: null, clients: new Set() });
  }
  return sessions.get(cid);
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

    ws.on('message', (data) => {
      // Forward every host message to all phone clients
      session.clients.forEach((client) => {
        if (client.readyState === 1) client.send(data);
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

    ws.on('message', (data) => {
      // Forward every client message to the host (plugin)
      if (session.host && session.host.readyState === 1) {
        session.host.send(data);
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
