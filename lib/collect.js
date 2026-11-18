'use strict';

const { execFile } = require('node:child_process');
const dns = require('node:dns');
const { isPrivateIp } = require('./classify');

const IS_WIN = process.platform === 'win32';

function run(file, args, timeout = 9000) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { maxBuffer: 8 * 1024 * 1024, timeout, windowsHide: true }, (err, stdout) => {
      if (err && !stdout) reject(err);
      else resolve(stdout || '');
    });
  });
}

/* ------------------------------------------------------------------ parsing */

function splitAddress(raw) {
  if (!raw || raw === '*:*' || raw === '*') return { host: '*', port: 0 };
  let host = raw;
  let port = 0;
  const idx = raw.lastIndexOf(':');
  if (idx !== -1) {
    host = raw.slice(0, idx);
    const parsed = Number(raw.slice(idx + 1));
    port = Number.isFinite(parsed) ? parsed : 0;
  }
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  return { host, port };
}

function parseWindowsNetstat(text) {
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!/^(TCP|UDP)\b/i.test(trimmed)) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 4) continue;
    const proto = parts[0].toLowerCase();
    const local = splitAddress(parts[1]);
    const remote = splitAddress(parts[2]);
    const pid = /^\d+$/.test(parts[parts.length - 1]) ? Number(parts[parts.length - 1]) : 0;
    let state = '';
    if (proto === 'tcp') {
      state = parts.length >= 5 && /^[A-Z_]+$/.test(parts[3]) ? parts[3] : 'UNKNOWN';
    } else {
      state = remote.port === 0 ? 'LISTENING' : 'BOUND';
    }
    rows.push({ proto, local, remote, state, pid });
  }
  return rows;
}

function parseSs(text) {
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!/^(tcp|udp)\b/i.test(trimmed)) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 6) continue;
    const proto = parts[0].toLowerCase().replace(/[46]$/, '');
    const state = parts[1];
    const local = splitAddress(parts[4]);
    const remote = splitAddress(parts[5]);
    let pid = 0;
    let process = '';
    const m = trimmed.match(/users:\(\("([^"]+)",pid=(\d+)/);
    if (m) {
      process = m[1];
      pid = Number(m[2]);
    }
    rows.push({
      proto,
      local,
      remote,
      state: state === 'UNCONN' || state === 'LISTEN' ? 'LISTENING' : state,
      pid,
      process
    });
  }
  return rows;
}

function parseUnixNetstat(text) {
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!/^(tcp|udp)[46]?\s/i.test(trimmed)) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 5) continue;
    const proto = parts[0].slice(0, 3).toLowerCase();
    const localRaw = parts[parts.length - 3];
    const remoteRaw = parts[parts.length - 2];
    const state = parts[parts.length - 1];
    const portOf = (raw) => {
      const seg = raw.split('.').pop();
      const n = Number(seg);
      return Number.isFinite(n) ? n : 0;
    };
    const hostOf = (raw) => raw.split('.').slice(0, -1).join('.');
    rows.push({
      proto,
      local: { host: hostOf(localRaw), port: portOf(localRaw) },
      remote: { host: hostOf(remoteRaw), port: portOf(remoteRaw) },
      state: state === 'LISTEN' ? 'LISTENING' : state,
      pid: 0
    });
  }
  return rows;
}

function parseTasklist(text) {
  const map = new Map();
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^"((?:[^"]|"")*)","(\d+)"/);
    if (m) map.set(Number(m[2]), m[1]);
  }
  return map;
}

function parsePs(text) {
  const map = new Map();
  for (const line of text.split(/\r?\n/)) {
    const m = line.trim().match(/^(\d+)\s+(.+)$/);
    if (m) map.set(Number(m[1]), m[2].split('/').pop());
  }
  return map;
}

/* ------------------------------------------------------------ process names */

let procCache = { map: new Map(), at: 0 };
let procPending = null;
let procLastForce = 0;
const procMisses = new Map();

async function getProcessMap(force = false) {
  if (force) {
    // Never hammer tasklist/ps: one forced refresh at a time, at most every 2s.
    if (Date.now() - procLastForce < 2000) return procCache.map;
    procLastForce = Date.now();
  } else if (procCache.map.size && Date.now() - procCache.at < 10_000) {
    return procCache.map;
  }
  if (procPending) return procPending;
  procPending = (async () => {
    try {
      const out = IS_WIN
        ? await run('tasklist', ['/FO', 'CSV', '/NH'], 9000)
        : await run('ps', ['-eo', 'pid=,comm='], 9000);
      procCache = { map: IS_WIN ? parseTasklist(out) : parsePs(out), at: Date.now() };
    } catch {
      procCache.at = Date.now();
    } finally {
      procPending = null;
    }
    return procCache.map;
  })();
  return procPending;
}

/* --------------------------------------------------------------- reverse DNS */

const dnsCache = new Map();
const dnsQueue = [];
let dnsActive = 0;
const DNS_CONCURRENCY = 6;
const DNS_TTL = 10 * 60 * 1000;

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('dns timeout')), ms))
  ]);
}

function pump() {
  while (dnsActive < DNS_CONCURRENCY && dnsQueue.length) {
    const host = dnsQueue.shift();
    dnsActive += 1;
    withTimeout(dns.promises.reverse(host), 1500)
      .then((names) => {
        dnsCache.set(host, { name: (names && names[0]) || null, at: Date.now() });
      })
      .catch(() => {
        dnsCache.set(host, { name: null, at: Date.now() });
      })
      .finally(() => {
        dnsActive -= 1;
        pump();
      });
  }
}

function primeHosts(hosts) {
  for (const host of hosts) {
    if (!host || isPrivateIp(host) || dnsCache.has(host)) continue;
    dnsCache.set(host, { name: null, at: Date.now() - DNS_TTL + 15_000, pending: true });
    dnsQueue.push(host);
  }
  pump();
}

function peekHost(host) {
  const entry = dnsCache.get(host);
  return entry && entry.name ? entry.name : null;
}

/* ------------------------------------------------------------------ collect */

async function collectConnections() {
  let rows = [];
  if (IS_WIN) {
    rows = parseWindowsNetstat(await run('netstat', ['-ano']));
  } else {
    try {
      rows = parseSs(await run('ss', ['-tunapH']));
    } catch {
      rows = parseUnixNetstat(await run('netstat', ['-an']));
    }
  }

  let procs = await getProcessMap();

  // The cached process list can lag behind brand new connections (a freshly
  // started app shows up as "pid 1234"). Re-read it when PIDs are unknown,
  // but retry the same PID at most once every 30s.
  const unknownPids = rows.filter((r) => r.pid > 0 && !procs.has(r.pid));
  if (unknownPids.length) {
    const now = Date.now();
    if (unknownPids.some((r) => now - (procMisses.get(r.pid) || 0) > 30_000)) {
      procs = await getProcessMap(true);
      for (const r of unknownPids) {
        if (procs.has(r.pid)) procMisses.delete(r.pid);
        else procMisses.set(r.pid, now);
      }
      if (procMisses.size > 1000) procMisses.clear();
    }
  }

  const seen = new Set();
  const connections = [];

  for (const row of rows) {
    const { proto, local, remote, state, pid } = row;
    if (!local.port && !remote.port) continue;
    if (state === 'TIME_WAIT' || state === 'CLOSE_WAIT') continue;

    const id = `${proto}|${local.host}:${local.port}|${remote.host}:${remote.port}|${state}|${pid}`;
    if (seen.has(id)) continue;
    seen.add(id);

    const isListener = state === 'LISTENING' || state === 'BOUND';
    const ip = isListener ? '' : remote.host;

    connections.push({
      id,
      proto,
      state,
      pid,
      process: row.process || procs.get(pid) || (pid === 0 ? 'idle' : `pid ${pid}`),
      local,
      remote,
      ip,
      hostname: ip ? peekHost(ip) : null,
      listener: isListener
    });
  }

  primeHosts(connections.filter((c) => !c.listener && c.ip).map((c) => c.ip));
  return connections;
}

module.exports = { collectConnections, peekHost, primeHosts, splitAddress };
