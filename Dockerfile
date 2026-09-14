FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
RUN npm ci && npx tsc -p tsconfig.json

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV MCP_RELAY_PORT=8790
ENV MCP_RELAY_HOST=0.0.0.0
ENV MCP_RELAY_DATA_DIR=/data
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
# DOCKH-CMP-002: Swarm, compose, and docker inspect had no way to tell a
# wedged-but-listening relay from a healthy one. Exec-form HEALTHCHECK plus
# a .cjs probe (package.json is type:module) so /bin/sh cannot expand $ and
# require() stays CJS. GET /health is unauthenticated. It is not /mcp and
# not our web. Uses node, not wget or curl. Written before USER so a failed
# write fails the build, then chown with /app.
RUN cat > /app/healthcheck.cjs << 'ENDHEALTH'
'use strict';
const fs = require('fs');
const http = require('http');
const https = require('https');

const HEALTH_PLAIN = 'AItomation MCP relay';
const TEAM_SPACE_PLAIN = 'AItomation Team Space bridge';
const BODY_MAX = 4096;
const REQ_TIMEOUT_MS = 4000;
const PORT_FALLBACK = 8790;
const PATH_MAX = 4096;
const PORT_RAW_MAX = 16;
const HOST_RAW_MAX = 256;

function stripEnv(s) {
  const raw = String(s == null ? '' : s);
  const cut = raw.indexOf('\0');
  const head = cut === -1 ? raw : raw.slice(0, cut);
  return head.replace(/[\r\n]/g, '').trim();
}

function isBannedPort(n) {
  return n === 3737 || n === 8765 || n === 8787 || n === 8788 || n === 8789 || n === 47600 || n === 47601;
}

function parseListenPort(raw) {
  const s = stripEnv(raw);
  if (s.length > PORT_RAW_MAX) return null;
  const n = Number(s || String(PORT_FALLBACK));
  if (!Number.isInteger(n) || n < 1 || n > 65535) return null;
  if (isBannedPort(n)) return null;
  return n;
}

function tlsListenState(certRaw, keyRaw, existsFn) {
  const cert = stripEnv(certRaw);
  const key = stripEnv(keyRaw);
  if (!cert && !key) return { tls: false };
  if (!cert || !key) return { refuse: true };
  if (cert.length > PATH_MAX || key.length > PATH_MAX) return { refuse: true };
  if (typeof existsFn !== 'function') return { refuse: true };
  try {
    if (!existsFn(cert) || !existsFn(key)) return { refuse: true };
  } catch (e) {
    return { refuse: true };
  }
  return { tls: true };
}

function probeHost(raw) {
  const h = stripEnv(raw);
  if (h.length > HOST_RAW_MAX) return null;
  if (!h || h === '0.0.0.0' || h === '127.0.0.1' || h === 'localhost') return '127.0.0.1';
  if (h === '::' || h === '::1') return '::1';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(h)) {
    const parts = h.split('.').map(function (p) { return Number(p); });
    if (parts.every(function (n) { return Number.isInteger(n) && n >= 0 && n <= 255; })) return h;
  }
  return null;
}

function healthyPlainBody(buf) {
  const text = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf == null ? '' : buf);
  if (text.indexOf(TEAM_SPACE_PLAIN) !== -1) return false;
  return text.indexOf(HEALTH_PLAIN) === 0;
}

function runProbe() {
  try {
    runProbeInner();
  } catch (e) {
    process.exit(1);
  }
}

function runProbeInner() {
  const port = parseListenPort(process.env.MCP_RELAY_PORT);
  if (port == null) process.exit(1);
  const tlsState = tlsListenState(
    process.env.MCP_RELAY_TLS_CERT_FILE,
    process.env.MCP_RELAY_TLS_KEY_FILE,
    function (p) {
      try { return fs.existsSync(p); } catch (e) { return false; }
    },
  );
  if (tlsState.refuse) process.exit(1);
  const host = probeHost(process.env.MCP_RELAY_HOST);
  if (!host) process.exit(1);
  const tls = tlsState.tls === true;
  const opts = {
    host: host,
    port: port,
    path: '/health',
    method: 'GET',
    timeout: REQ_TIMEOUT_MS,
    headers: { Accept: 'text/plain' },
  };
  if (host.indexOf(':') !== -1) opts.family = 6;
  if (tls) opts.rejectUnauthorized = false;
  const req = (tls ? https : http).request(opts, function (res) {
    if (res.statusCode !== 200) {
      res.resume();
      process.exit(1);
    }
    const chunks = [];
    let n = 0;
    res.on('data', function (c) {
      n += c.length;
      if (n > BODY_MAX) {
        try { res.destroy(); } catch (e) {}
        process.exit(1);
      }
      chunks.push(c);
    });
    res.on('end', function () {
      process.exit(healthyPlainBody(Buffer.concat(chunks)) ? 0 : 1);
    });
    res.on('error', function () { process.exit(1); });
  });
  req.on('timeout', function () {
    try { req.destroy(); } catch (e) {}
    process.exit(1);
  });
  req.on('error', function () {
    try { req.destroy(); } catch (e) {}
    process.exit(1);
  });
  req.end();
}

module.exports = {
  stripEnv: stripEnv,
  parseListenPort: parseListenPort,
  tlsListenState: tlsListenState,
  probeHost: probeHost,
  healthyPlainBody: healthyPlainBody,
  isBannedPort: isBannedPort,
  HEALTH_PLAIN: HEALTH_PLAIN,
  TEAM_SPACE_PLAIN: TEAM_SPACE_PLAIN,
  BODY_MAX: BODY_MAX,
  PORT_FALLBACK: PORT_FALLBACK,
  REQ_TIMEOUT_MS: REQ_TIMEOUT_MS,
  PATH_MAX: PATH_MAX,
  PORT_RAW_MAX: PORT_RAW_MAX,
  HOST_RAW_MAX: HOST_RAW_MAX,
};

if (require.main === module) runProbe();
ENDHEALTH
RUN addgroup -S mcprelay && adduser -S -G mcprelay mcprelay \
  && mkdir -p /data \
  && chown -R mcprelay:mcprelay /app /data \
  && chmod 700 /data \
  && test -s /app/healthcheck.cjs
USER mcprelay
VOLUME ["/data"]
EXPOSE 8790
# DOCKH-CMP-002: /health only. Exec form (no shell). TLS uses https plus
# rejectUnauthorized:false on loopback. Not a probe of our web /mcp.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "/app/healthcheck.cjs"]
CMD ["node", "dist/server.js"]
