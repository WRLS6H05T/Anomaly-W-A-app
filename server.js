'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { Monitor } = require('./lib/monitor');

const requestedPort = Number.parseInt(process.env.NETWATCH_PORT ?? '', 10);
const PORT = Number.isFinite(requestedPort) && requestedPort > 0 && requestedPort < 65536 ? requestedPort : 4177;
const HOST = process.env.NETWATCH_HOST || '127.0.0.1';
const requestedPoll = Number.parseInt(process.env.NETWATCH_POLL_MS ?? '', 10);
const POLL_MS = Number.isFinite(requestedPoll) && requestedPoll >= 1000 ? requestedPoll : 2500;
const PUBLIC_DIR = path.join(__dirname, 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8'
};

const monitor = new Monitor({ pollMs: POLL_MS });
const clients = new Set();

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store'
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 64 * 1024) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function broadcast() {
  if (!clients.size) return;
  const payload = `data: ${JSON.stringify(monitor.snapshot)}\n\n`;
  for (const res of clients) {
    try {
      res.write(payload);
    } catch {
      clients.delete(res);
    }
  }
}

function openStream(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.write(`retry: 2000\n\n`);
  res.write(`data: ${JSON.stringify(monitor.snapshot)}\n\n`);
  clients.add(res);
  const beat = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch {
      clearInterval(beat);
    }
  }, 15000);
  req.on('close', () => {
    clearInterval(beat);
    clients.delete(res);
  });
}

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
  const target = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!target.startsWith(PUBLIC_DIR)) {
    res.writeHead(403).end('Forbidden');
    return;
  }
  fs.readFile(target, (err, buf) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(target).toLowerCase()] || 'application/octet-stream',
      'Content-Length': buf.length,
      'Cache-Control': 'no-store'
    });
    res.end(buf);
  });
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const { pathname } = url;

  if (pathname === '/api/state' && req.method === 'GET') {
    return sendJson(res, 200, monitor.snapshot);
  }
  if (pathname === '/api/stream' && req.method === 'GET') {
    return openStream(req, res);
  }

  if (req.method === 'POST' && pathname.startsWith('/api/')) {
    let body = {};
    try {
      body = await readBody(req);
    } catch (err) {
      return sendJson(res, 400, { error: err.message });
    }

    if (pathname === '/api/trust') {
      const state = monitor.trust(String(body.ip || ''));
      broadcast();
      return sendJson(res, 200, state);
    }
    if (pathname === '/api/untrust') {
      const state = monitor.untrust(String(body.ip || ''));
      broadcast();
      return sendJson(res, 200, state);
    }
    if (pathname === '/api/ack') {
      const state = monitor.acknowledge(String(body.key || ''));
      broadcast();
      return sendJson(res, 200, state);
    }
    if (pathname === '/api/alerts/clear') {
      const state = monitor.clearFeed();
      broadcast();
      return sendJson(res, 200, state);
    }
    if (pathname === '/api/baseline') {
      const state = monitor.baselineNow();
      broadcast();
      return sendJson(res, 200, state);
    }
    return sendJson(res, 404, { error: 'unknown action' });
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    return serveStatic(req, res, pathname);
  }

  res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Method not allowed');
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error('[netwatch] request failed:', err);
    if (!res.headersSent) sendJson(res, 500, { error: 'internal error' });
    else res.end();
  });
});

async function loop() {
  await monitor.tick();
  broadcast();
  setTimeout(loop, POLL_MS).unref?.();
}

server.listen(PORT, HOST, () => {
  const address = server.address();
  const boundPort = typeof address === 'object' && address ? address.port : PORT;
  monitor.tick().then(() => broadcast());
  setTimeout(loop, POLL_MS).unref?.();
  console.log(
    `[netwatch] listening on http://${HOST}:${boundPort} (pid ${process.pid}, poll ${POLL_MS}ms)`
  );
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    monitor.save();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 800).unref();
  });
}
