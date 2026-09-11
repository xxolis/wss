/**
 * ws-relay: a WebSocket <-> TCP relay with multi-stream support.
 *
 * Purpose: let a browser-based "OS" (which can't open raw sockets)
 * reach real network services by tunneling through this server.
 * Multiple logical TCP connections (e.g. one to a web server, one to
 * a Minecraft server on 25565, one to an SSH host) can run concurrently
 * over a SINGLE WebSocket connection.
 *
 * Protocol:
 *   Control messages (WS text frames, JSON):
 *     -> {"type":"connect","streamId":<number>,"host":"...","port":<number>}
 *     <- {"type":"connected","streamId":<number>}
 *     <- {"type":"error","streamId":<number>,"message":"..."}
 *     -> {"type":"close","streamId":<number>}
 *     <- {"type":"closed","streamId":<number>}
 *
 *   Data messages (WS binary frames):
 *     [4-byte big-endian streamId][raw payload bytes]
 *     Used both directions once a stream is "connected".
 *
 * The client picks its own streamId (any unique uint32 per connection)
 * so it can open as many concurrent streams as it needs.
 *
 * Ports: NOT restricted by default (all ports, including things like
 * 25565, are reachable). Set ALLOWED_PORTS if you ever want to restrict.
 * Hosts: open by default too, except common private/internal IP ranges
 * (basic SSRF guard). Set ALLOWED_HOSTS to lock this down further.
 */

const { WebSocketServer } = require('ws');
const net = require('net');
const http = require('http');

// ---- Config -----------------------------------------------------------
const PORT = process.env.PORT || 8080;
const AUTH_TOKEN = process.env.RELAY_TOKEN || null; // set this before deploying anywhere public!
const ALLOWED_HOSTS = process.env.ALLOWED_HOSTS
  ? process.env.ALLOWED_HOSTS.split(',').map((h) => h.trim())
  : null; // null = allow any public host (private ranges still blocked below)
const ALLOWED_PORTS = process.env.ALLOWED_PORTS
  ? process.env.ALLOWED_PORTS.split(',').map((p) => parseInt(p, 10))
  : null; // null = ALL ports allowed, e.g. 25565 for Minecraft

// ---- HTTP server (health check for Railway etc.) -----------------------
const httpServer = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ server: httpServer });

const BLOCKED_HOST_PATTERNS = [
  /^127\./, /^10\./, /^192\.168\./, /^169\.254\./,
  /^localhost$/i, /^0\.0\.0\.0$/, /^::1$/,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
];

function isHostAllowed(host) {
  if (ALLOWED_HOSTS) return ALLOWED_HOSTS.includes(host);
  return !BLOCKED_HOST_PATTERNS.some((re) => re.test(host));
}

function isPortAllowed(port) {
  if (!ALLOWED_PORTS) return true; // all ports allowed by default
  return ALLOWED_PORTS.includes(port);
}

// ---- Frame helpers: [4-byte BE streamId][payload] ----------------------
function encodeFrame(streamId, payload) {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(streamId >>> 0, 0);
  return Buffer.concat([header, payload]);
}

function decodeFrame(buf) {
  const streamId = buf.readUInt32BE(0);
  const payload = buf.subarray(4);
  return { streamId, payload };
}

wss.on('connection', (ws, req) => {
  // --- Auth check ---
  if (AUTH_TOKEN) {
    const url = new URL(req.url, 'http://localhost');
    if (url.searchParams.get('token') !== AUTH_TOKEN) {
      ws.close(4001, 'unauthorized');
      return;
    }
  }

  const streams = new Map(); // streamId -> net.Socket

  const sendJSON = (obj) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
  };

  ws.on('message', (data, isBinary) => {
    if (!isBinary) {
      let msg;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return; // ignore malformed control messages
      }

      if (msg.type === 'connect') {
        const { streamId, host, port } = msg;

        if (typeof streamId !== 'number' || !host || !port) {
          sendJSON({ type: 'error', streamId, message: 'missing streamId/host/port' });
          return;
        }
        if (streams.has(streamId)) {
          sendJSON({ type: 'error', streamId, message: 'streamId already in use' });
          return;
        }
        if (!isHostAllowed(host)) {
          sendJSON({ type: 'error', streamId, message: `host not allowed: ${host}` });
          return;
        }
        if (!isPortAllowed(port)) {
          sendJSON({ type: 'error', streamId, message: `port not allowed: ${port}` });
          return;
        }

        const sock = net.connect({ host, port }, () => {
          sendJSON({ type: 'connected', streamId });
        });

        sock.on('data', (chunk) => {
          if (ws.readyState === ws.OPEN) ws.send(encodeFrame(streamId, chunk));
        });

        sock.on('error', (err) => {
          sendJSON({ type: 'error', streamId, message: err.message });
          streams.delete(streamId);
        });

        sock.on('close', () => {
          sendJSON({ type: 'closed', streamId });
          streams.delete(streamId);
        });

        streams.set(streamId, sock);
        return;
      }

      if (msg.type === 'close') {
        const sock = streams.get(msg.streamId);
        if (sock) {
          sock.destroy();
          streams.delete(msg.streamId);
        }
        return;
      }

      return;
    }

    // Binary frame: route to the right TCP stream.
    const { streamId, payload } = decodeFrame(data);
    const sock = streams.get(streamId);
    if (sock) sock.write(payload);
  });

  const cleanup = () => {
    for (const sock of streams.values()) sock.destroy();
    streams.clear();
  };
  ws.on('close', cleanup);
  ws.on('error', cleanup);
});

httpServer.listen(PORT, () => {
  console.log(`ws-relay listening on :${PORT}`);
  console.log(`auth: ${AUTH_TOKEN ? 'enabled' : 'DISABLED (set RELAY_TOKEN before deploying publicly!)'}`);
  console.log(`ports: ${ALLOWED_PORTS ? ALLOWED_PORTS.join(', ') : 'ALL (no restriction)'}`);
  console.log(`hosts: ${ALLOWED_HOSTS ? ALLOWED_HOSTS.join(', ') : 'any public host (private IP ranges blocked by default)'}`);
});
