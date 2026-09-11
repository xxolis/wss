'use strict';

/**
 * ws-relay
 *
 * WebSocket <-> TCP relay with multiple logical TCP streams over one
 * WebSocket connection.
 *
 * Railway-ready:
 *   - Uses Railway's PORT environment variable
 *   - HTTP /health endpoint
 *   - WebSocket support
 *   - Optional token authentication (strongly recommended)
 *   - DNS-based SSRF protection
 *   - Private/reserved IP blocking
 *   - Host/port allowlists
 *   - Stream limits
 *   - TCP idle timeout
 *   - WebSocket message-size limit
 *   - Strict protocol validation
 *
 * Protocol:
 *
 * Client -> Server (WS text):
 *   {"type":"connect","streamId":1,"host":"example.com","port":443}
 *
 * Server -> Client:
 *   {"type":"connected","streamId":1}
 *   {"type":"error","streamId":1,"message":"..."}
 *   {"type":"closed","streamId":1}
 *
 * Data (WS binary):
 *   [4-byte big-endian uint32 streamId][raw TCP payload]
 *
 * Client -> Server binary frames write to the selected TCP stream.
 * Server -> Client binary frames contain data read from TCP.
 */

// ---------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------

const http = require('http');
const net = require('net');
const dns = require('dns').promises;
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

const PORT = parsePositiveInt(process.env.PORT, 8080);

const RELAY_TOKEN = process.env.RELAY_TOKEN || null;

const MAX_STREAMS = parsePositiveInt(
  process.env.MAX_STREAMS,
  32
);

const MAX_WS_MESSAGE_SIZE = parsePositiveInt(
  process.env.MAX_WS_MESSAGE_SIZE,
  1024 * 1024 // 1 MB
);

const TCP_IDLE_TIMEOUT_MS = parsePositiveInt(
  process.env.TCP_IDLE_TIMEOUT_MS,
  10 * 60 * 1000 // 10 minutes
);

const CONNECT_TIMEOUT_MS = parsePositiveInt(
  process.env.CONNECT_TIMEOUT_MS,
  15 * 1000
);

const MAX_HOST_LENGTH = 253;

const ALLOWED_PORTS = parseCsvInts(process.env.ALLOWED_PORTS);

const ALLOWED_HOSTS = parseCsvStrings(process.env.ALLOWED_HOSTS);

const TRUST_PROXY = process.env.TRUST_PROXY === 'true';

// ---------------------------------------------------------------------
// Startup validation
// ---------------------------------------------------------------------

if (!RELAY_TOKEN) {
  console.warn(
    '[SECURITY] RELAY_TOKEN is not set. Authentication is DISABLED.'
  );
  console.warn(
    '[SECURITY] Set RELAY_TOKEN before exposing this relay publicly.'
  );
}

if (ALLOWED_PORTS) {
  console.log(`[config] allowed ports: ${ALLOWED_PORTS.join(', ')}`);
} else {
  console.log('[config] allowed ports: ALL');
}

if (ALLOWED_HOSTS) {
  console.log(`[config] allowed hosts: ${ALLOWED_HOSTS.join(', ')}`);
} else {
  console.log('[config] allowed hosts: public addresses');
}

console.log(`[config] max streams/client: ${MAX_STREAMS}`);
console.log(`[config] TCP idle timeout: ${TCP_IDLE_TIMEOUT_MS} ms`);

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

function parsePositiveInt(value, fallback) {
  const n = Number.parseInt(value, 10);

  if (!Number.isInteger(n) || n <= 0) {
    return fallback;
  }

  return n;
}

function parseCsvInts(value) {
  if (!value) return null;

  const values = value
    .split(',')
    .map((v) => Number.parseInt(v.trim(), 10))
    .filter((v) => Number.isInteger(v));

  return values.length ? values : null;
}

function parseCsvStrings(value) {
  if (!value) return null;

  const values = value
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);

  return values.length ? values : null;
}

function isValidStreamId(value) {
  return (
    Number.isInteger(value) &&
    value >= 0 &&
    value <= 0xffffffff
  );
}

function isValidPort(value) {
  return (
    Number.isInteger(value) &&
    value >= 1 &&
    value <= 65535
  );
}

function normalizeHost(host) {
  if (typeof host !== 'string') {
    return null;
  }

  host = host.trim();

  if (!host || host.length > MAX_HOST_LENGTH) {
    return null;
  }

  // Reject control characters, whitespace and obviously malformed values.
  if (/[\x00-\x20\x7f]/.test(host)) {
    return null;
  }

  // Remove surrounding IPv6 brackets if supplied.
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }

  return host.toLowerCase();
}

function isPortAllowed(port) {
  return !ALLOWED_PORTS || ALLOWED_PORTS.includes(port);
}

function isHostAllowedByAllowlist(host) {
  if (!ALLOWED_HOSTS) {
    return true;
  }

  return ALLOWED_HOSTS.includes(host);
}

// ---------------------------------------------------------------------
// IP validation / SSRF protection
// ---------------------------------------------------------------------

function ipv4ToInteger(ip) {
  const parts = ip.split('.');

  if (parts.length !== 4) return null;

  let result = 0;

  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;

    const n = Number(part);

    if (n < 0 || n > 255) return null;

    result = result * 256 + n;
  }

  return result;
}

function isPrivateIPv4(ip) {
  const n = ipv4ToInteger(ip);

  if (n === null) return false;

  const ranges = [
    // 0.0.0.0/8
    [0x00000000, 0x00ffffff],

    // 10.0.0.0/8
    [0x0a000000, 0x0affffff],

    // 100.64.0.0/10 - carrier-grade NAT
    [0x64400000, 0x647fffff],

    // 127.0.0.0/8 - loopback
    [0x7f000000, 0x7fffffff],

    // 169.254.0.0/16 - link local
    [0xa9fe0000, 0xa9feffff],

    // 172.16.0.0/12
    [0xac100000, 0xac1fffff],

    // 192.0.0.0/24
    [0xc0000000, 0xc00000ff],

    // 192.0.2.0/24 - documentation
    [0xc0000200, 0xc00002ff],

    // 192.168.0.0/16
    [0xc0a80000, 0xc0a8ffff],

    // 198.18.0.0/15 - benchmarking
    [0xc6120000, 0xc613ffff],

    // 198.51.100.0/24 - documentation
    [0xc6336400, 0xc63364ff],

    // 203.0.113.0/24 - documentation
    [0xcb007100, 0xcb0071ff],

    // 224.0.0.0/4 - multicast
    [0xe0000000, 0xefffffff],

    // 240.0.0.0/4 - reserved
    [0xf0000000, 0xffffffff],
  ];

  return ranges.some(([start, end]) => n >= start && n <= end);
}

function normalizeIPv4MappedIPv6(ip) {
  const match = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);

  return match ? match[1] : null;
}

function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();

  if (
    normalized === '::' ||
    normalized === '::1'
  ) {
    return true;
  }

  const mappedIPv4 = normalizeIPv4MappedIPv6(normalized);

  if (mappedIPv4) {
    return isPrivateIPv4(mappedIPv4);
  }

  // fc00::/7 - unique local addresses
  if (/^f[cd][0-9a-f]{2}:/i.test(normalized)) {
    return true;
  }

  // fe80::/10 - link local
  if (/^fe[89ab][0-9a-f]:/i.test(normalized)) {
    return true;
  }

  // ff00::/8 - multicast
  if (/^ff[0-9a-f]{2}:/i.test(normalized)) {
    return true;
  }

  return false;
}

function isBlockedAddress(address) {
  const family = net.isIP(address);

  if (family === 4) {
    return isPrivateIPv4(address);
  }

  if (family === 6) {
    return isPrivateIPv6(address);
  }

  return true;
}

async function resolvePublicAddresses(host) {
  // If it's already an IP, validate it directly.
  const family = net.isIP(host);

  if (family) {
    if (isBlockedAddress(host)) {
      throw new Error('destination IP is private or reserved');
    }

    return [{ address: host, family }];
  }

  let records;

  try {
    records = await dns.lookup(host, {
      all: true,
      verbatim: true,
    });
  } catch {
    throw new Error('DNS lookup failed');
  }

  if (!records.length) {
    throw new Error('hostname did not resolve');
  }

  for (const record of records) {
    if (isBlockedAddress(record.address)) {
      throw new Error(
        'hostname resolves to a private or reserved IP'
      );
    }
  }

  return records;
}

// ---------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------

const httpServer = http.createServer((req, res) => {
  // Health endpoint for Railway.
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    });

    res.end('ok');
    return;
  }

  res.writeHead(404, {
    'Content-Type': 'text/plain; charset=utf-8',
  });

  res.end('Not found');
});

// ---------------------------------------------------------------------
// WebSocket server
// ---------------------------------------------------------------------

const wss = new WebSocketServer({
  server: httpServer,

  // Prevent clients from sending enormous WS messages.
  maxPayload: MAX_WS_MESSAGE_SIZE,

  // Disable compression for a TCP relay.
  // Compression adds CPU overhead and usually isn't useful here.
  perMessageDeflate: false,
});

// ---------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------

function isAuthenticated(req) {
  if (!RELAY_TOKEN) {
    return true;
  }

  const url = new URL(
    req.url || '/',
    'http://localhost'
  );

  const token = url.searchParams.get('token');

  if (!token) {
    return false;
  }

  // Timing-safe comparison.
  const expected = Buffer.from(RELAY_TOKEN);
  const received = Buffer.from(token);

  if (expected.length !== received.length) {
    return false;
  }

  return crypto.timingSafeEqual(expected, received);
}

// ---------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------

wss.on('connection', (ws, req) => {
  if (!isAuthenticated(req)) {
    ws.close(4001, 'unauthorized');
    return;
  }

  const streams = new Map();

  let closed = false;

  function sendJSON(obj) {
    if (
      !closed &&
      ws.readyState === WebSocket.OPEN
    ) {
      ws.send(JSON.stringify(obj));
    }
  }

  function sendError(streamId, message) {
    sendJSON({
      type: 'error',
      streamId,
      message,
    });
  }

  function destroyStream(streamId, reason = 'closed') {
    const sock = streams.get(streamId);

    if (!sock) {
      return;
    }

    streams.delete(streamId);

    sock.removeAllListeners('data');

    if (!sock.destroyed) {
      sock.destroy();
    }

    sendJSON({
      type: 'closed',
      streamId,
      reason,
    });
  }

  // ---------------------------------------------------------------
  // CONNECT
  // ---------------------------------------------------------------

  async function handleConnect(msg) {
    const streamId = msg.streamId;
    const port = msg.port;
    const host = normalizeHost(msg.host);

    if (!isValidStreamId(streamId)) {
      sendError(
        streamId,
        'streamId must be an integer from 0 to 4294967295'
      );
      return;
    }

    if (!host) {
      sendError(
        streamId,
        'invalid host'
      );
      return;
    }

    if (!isValidPort(port)) {
      sendError(
        streamId,
        'port must be an integer from 1 to 65535'
      );
      return;
    }

    if (streams.has(streamId)) {
      sendError(
        streamId,
        'streamId already in use'
      );
      return;
    }

    if (streams.size >= MAX_STREAMS) {
      sendError(
        streamId,
        `maximum streams reached (${MAX_STREAMS})`
      );
      return;
    }

    if (!isHostAllowedByAllowlist(host)) {
      sendError(
        streamId,
        'host is not allowed'
      );
      return;
    }

    if (!isPortAllowed(port)) {
      sendError(
        streamId,
        'port is not allowed'
      );
      return;
    }

    let addresses;

    try {
      addresses = await resolvePublicAddresses(host);
    } catch (err) {
      sendError(
        streamId,
        err.message || 'destination rejected'
      );
      return;
    }

    if (closed) {
      return;
    }

    // DNS is resolved and checked before connecting.
    //
    // We connect to the validated IP rather than resolving the hostname
    // again inside net.connect(), preventing a basic DNS-rebinding race.
    const target = addresses[0];

    const sock = new net.Socket();

    let connected = false;
    let idleTimer = null;
    let connectTimer = null;

    function resetIdleTimer() {
      if (idleTimer) {
        clearTimeout(idleTimer);
      }

      idleTimer = setTimeout(() => {
        sendError(
          streamId,
          'TCP connection idle timeout'
        );

        destroyStream(streamId, 'idle timeout');
      }, TCP_IDLE_TIMEOUT_MS);
    }

    function cleanupTimers() {
      if (idleTimer) {
        clearTimeout(idleTimer);
        idleTimer = null;
      }

      if (connectTimer) {
        clearTimeout(connectTimer);
        connectTimer = null;
      }
    }

    streams.set(streamId, sock);

    connectTimer = setTimeout(() => {
      if (!connected) {
        sendError(
          streamId,
          'TCP connection timeout'
        );

        sock.destroy();
      }
    }, CONNECT_TIMEOUT_MS);

    sock.setNoDelay(true);

    sock.on('connect', () => {
      connected = true;

      if (connectTimer) {
        clearTimeout(connectTimer);
        connectTimer = null;
      }

      resetIdleTimer();

      sendJSON({
        type: 'connected',
        streamId,
      });
    });

    sock.on('data', (chunk) => {
      resetIdleTimer();

      if (
        ws.readyState === WebSocket.OPEN
      ) {
        const header = Buffer.allocUnsafe(4);
        header.writeUInt32BE(
          streamId >>> 0,
          0
        );

        ws.send(
          Buffer.concat([header, chunk])
        );
      }
    });

    sock.on('error', (err) => {
      cleanupTimers();

      if (streams.has(streamId)) {
        streams.delete(streamId);

        sendError(
          streamId,
          err.message || 'TCP connection error'
        );
      }
    });

    sock.on('close', () => {
      cleanupTimers();

      if (streams.has(streamId)) {
        streams.delete(streamId);

        sendJSON({
          type: 'closed',
          streamId,
        });
      }
    });

    sock.connect({
      host: target.address,
      port,
      family: target.family,
    });
  }

  // ---------------------------------------------------------------
  // MESSAGE
  // ---------------------------------------------------------------

  ws.on('message', (data, isBinary) => {
    if (closed) {
      return;
    }

    // Binary frame:
    // [4-byte BE streamId][payload]
    if (isBinary) {
      const buf = Buffer.isBuffer(data)
        ? data
        : Buffer.from(data);

      if (buf.length < 4) {
        sendJSON({
          type: 'error',
          message: 'binary frame must contain a 4-byte streamId',
        });
        return;
      }

      const streamId = buf.readUInt32BE(0);
      const payload = buf.subarray(4);

      const sock = streams.get(streamId);

      if (!sock || sock.destroyed) {
        return;
      }

      sock.write(payload);
      return;
    }

    // Text control frame.
    let msg;

    try {
      msg = JSON.parse(data.toString());
    } catch {
      sendJSON({
        type: 'error',
        message: 'invalid JSON',
      });

      return;
    }

    if (!msg || typeof msg !== 'object') {
      sendJSON({
        type: 'error',
        message: 'control message must be an object',
      });

      return;
    }

    if (msg.type === 'connect') {
      void handleConnect(msg);
      return;
    }

    if (msg.type === 'close') {
      if (!isValidStreamId(msg.streamId)) {
        sendError(
          msg.streamId,
          'invalid streamId'
        );
        return;
      }

      destroyStream(
        msg.streamId,
        'client requested close'
      );

      return;
    }

    sendJSON({
      type: 'error',
      message: `unknown message type: ${String(msg.type)}`,
    });
  });

  // ---------------------------------------------------------------
  // CLOSE / ERROR
  // ---------------------------------------------------------------

  function cleanup() {
    if (closed) {
      return;
    }

    closed = true;

    for (const sock of streams.values()) {
      sock.destroy();
    }

    streams.clear();
  }

  ws.on('close', cleanup);
  ws.on('error', cleanup);
});

// ---------------------------------------------------------------------
// HTTP/WebSocket server startup
// ---------------------------------------------------------------------

httpServer.on('error', (err) => {
  console.error('[server] HTTP server error:', err);
});

wss.on('error', (err) => {
  console.error('[server] WebSocket server error:', err);
});

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(
    `[server] ws-relay listening on 0.0.0.0:${PORT}`
  );

  console.log(
    `[server] authentication: ${
      RELAY_TOKEN ? 'enabled' : 'DISABLED'
    }`
  );

  console.log(
    `[server] max streams: ${MAX_STREAMS}`
  );
});
