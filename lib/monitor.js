'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { collectConnections } = require('./collect');
const { classify, isLoopback, isPrivateIp, SEVERITY_RANK } = require('./classify');

const DATA_DIR = path.join(__dirname, '..', 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const MAX_FEED = 120;
const MAX_NOTIFIED = 3000;

function emptyState() {
  return {
    version: 1,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    baselineAt: 0,
    seenEndpoints: {},
    seenProcesses: {},
    trustedIps: {},
    muted: {},
    notified: {},
    feed: []
  };
}

function loadState() {
  try {
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return { ...emptyState(), ...parsed };
  } catch {
    return null;
  }
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function pruneMap(map, limit) {
  const keys = Object.keys(map);
  if (keys.length <= limit) return map;
  keys
    .sort((a, b) => (map[a] || 0) - (map[b] || 0))
    .slice(0, keys.length - limit)
    .forEach((k) => delete map[k]);
  return map;
}

class Monitor {
  constructor({ pollMs = 2500 } = {}) {
    this.pollMs = pollMs;
    const loaded = loadState();
    this.state = loaded || emptyState();
    this.feed = Array.isArray(this.state.feed) ? this.state.feed.slice(0, MAX_FEED) : [];
    this.lastConns = [];
    this.ticking = false;
    this.dirty = false;
    this.scanError = null;
    this.snapshot = this.buildSnapshot();
    this.saveTimer = setInterval(() => this.save(), 4000);
    this.saveTimer.unref?.();
  }

  /* ------------------------------------------------------------- persistence */

  save() {
    if (!this.dirty) return;
    this.dirty = false;
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      this.state.feed = this.feed.slice(0, MAX_FEED);
      this.state.updatedAt = Date.now();
      fs.writeFileSync(STATE_FILE, JSON.stringify(this.state, null, 2));
    } catch (err) {
      console.error('[netwatch] could not persist state:', err.message);
    }
  }

  /* ---------------------------------------------------------------- scanning */

  async tick() {
    if (this.ticking) return this.snapshot;
    this.ticking = true;
    try {
      const raw = await collectConnections();
      this.scanError = null;
      this.evaluate(raw);
    } catch (err) {
      this.scanError = err.message || String(err);
      console.error('[netwatch] scan failed:', this.scanError);
    } finally {
      this.ticking = false;
    }
    return this.snapshot;
  }

  evaluate(raw) {
    const now = Date.now();
    const { seenEndpoints, seenProcesses, trustedIps } = this.state;
    const firstPass = !this.state.baselineAt;

    const listenerPorts = new Set(
      raw.filter((c) => c.listener).map((c) => c.local.port)
    );

    const candidates = [];
    const conns = [];

    for (const c of raw) {
      // A listener bound to 0.0.0.0/:: has no remote peer: it is not loopback traffic.
      const remoteLoopback = !c.listener && isLoopback(c.remote.host);
      const loopback = !c.listener && (remoteLoopback || isLoopback(c.local.host));
      const info = classify(c.listener ? c.local.port : c.remote.port, c.proto);
      const exposed =
        c.listener && (c.local.host === '0.0.0.0' || c.local.host === '::' || c.local.host === '*');
      const inbound = !c.listener && listenerPorts.has(c.local.port) && !remoteLoopback;
      const direction = c.listener ? 'listener' : inbound ? 'inbound' : loopback ? 'loopback' : 'outbound';
      const ip = c.listener ? c.local.host : c.remote.host;
      const process = c.process;
      const trusted = !!trustedIps[ip];
      const internal = c.listener || loopback || remoteLoopback;

      let riskBase = 0;
      if (info.mode === 'plaintext') {
        if (c.listener) {
          riskBase = exposed ? 45 + (SEVERITY_RANK[info.severity] || 2) * 10 : 0;
        } else if (!remoteLoopback) {
          riskBase = 50 + (SEVERITY_RANK[info.severity] || 2) * 10;
        }
      }

      const conn = {
        id: c.id,
        proto: c.proto,
        state: c.state,
        pid: c.pid,
        process,
        local: c.local,
        remote: c.remote,
        hostname: c.hostname,
        ip,
        direction,
        listener: c.listener,
        inbound,
        exposed,
        loopback,
        internal,
        service: info.service,
        encryption: info.mode,
        severity: info.severity,
        why: info.why,
        knownPort: info.known,
        trusted,
        verified: internal || trusted || !!seenEndpoints[ip],
        riskBase
      };

      /* ------------------------------------------------ plaintext candidates */
      if (info.mode === 'plaintext' && info.severity) {
        if (c.listener) {
          if (exposed && (info.severity === 'high' || info.severity === 'critical')) {
            candidates.push({
              key: `exposure:${c.local.host}:${c.local.port}:${process}`,
              type: 'exposed-service',
              severity: info.severity,
              title: `Unencrypted ${info.service} reachable on all interfaces`,
              detail: `${process} is listening on ${ip}:${c.local.port} without encryption. ${info.why}`,
              // A wildcard bind address is not something you can trust, so the
              // alert is not tied to an IP and offers no "Trust" action.
              ip: '',
              process,
              port: c.local.port,
              service: info.service
            });
          }
        } else if (!remoteLoopback) {
          candidates.push({
            key: `plaintext:${ip}:${c.remote.port}:${info.service}`,
            type: 'unencrypted-traffic',
            severity: info.severity || 'medium',
            title: `Unencrypted ${info.service} traffic`,
            detail: `${process} → ${ip}:${c.remote.port}. ${info.why}`,
            ip,
            process,
            port: c.remote.port,
            service: info.service
          });
        }
      }

      /* -------------------------------------------- unverified activity signs */
      if (!internal && !trusted) {
        if (!seenEndpoints[ip]) {
          candidates.push({
            key: `endpoint:${ip}`,
            type: 'unverified-endpoint',
            severity: isPrivateIp(ip) ? 'low' : 'medium',
            title: 'Unverified remote endpoint contacted',
            detail: `${process} opened ${c.proto.toUpperCase()} ${ip}:${c.remote.port} (${
              info.service
            }) — this host was never seen before in the baseline.`,
            ip,
            process,
            port: c.remote.port,
            service: info.service
          });
        }
        if (!seenProcesses[process]) {
          candidates.push({
            key: `process:${process}`,
            type: 'unverified-process',
            severity: 'medium',
            title: 'Unverified process using the network',
            detail: `${process} (PID ${c.pid}) is communicating with ${ip}:${c.remote.port} and is not part of the baseline.`,
            ip,
            process,
            port: c.remote.port,
            service: info.service
          });
        }
      }

      conns.push(conn);
    }

    /* --------------------------------------------------------------- baseline */
    if (firstPass) {
      for (const c of conns) {
        if (c.listener) continue;
        if (c.ip && c.ip !== '*') this.state.seenEndpoints[c.ip] = this.state.seenEndpoints[c.ip] || now;
        if (c.ip && c.ip !== '*') this.state.seenProcesses[c.process] = this.state.seenProcesses[c.process] || now;
      }
      this.state.baselineAt = now;
      this.feed.unshift({
        id: `system:${now}`,
        type: 'system',
        severity: 'info',
        title: 'Baseline established',
        detail: `Recorded ${Object.keys(this.state.seenEndpoints).length} endpoints and ${
          Object.keys(this.state.seenProcesses).length
        } processes. Anything new from here on is reported as unverified.`,
        at: now
      });
      this.dirty = true;
    } else {
      for (const candidate of candidates) {
        const key = candidate.key;
        if (this.state.muted[key] || this.state.notified[key]) continue;
        this.state.notified[key] = now;
        this.feed.unshift({ ...candidate, id: key, at: now });
      }
    }

    /* ------------------------------------------------- grow the learned baseline */
    for (const c of conns) {
      if (!c.ip || c.ip === '*' || c.ip === '0.0.0.0' || c.ip === '::') continue;
      if (!this.state.seenProcesses[c.process]) {
        this.state.seenProcesses[c.process] = now;
        this.dirty = true;
      }
      if (c.listener) continue;
      if (!this.state.seenEndpoints[c.ip]) {
        this.state.seenEndpoints[c.ip] = now;
        this.dirty = true;
      }
    }

    this.feed = this.feed.slice(0, MAX_FEED);
    pruneMap(this.state.notified, MAX_NOTIFIED);
    this.lastConns = conns;
    this.snapshot = this.buildSnapshot();
    this.dirty = true;
  }

  /* ------------------------------------------------------------------ view */

  buildSnapshot() {
    const { trustedIps, seenEndpoints } = this.state;
    const conns = this.lastConns.map((c) => {
      const trusted = !!trustedIps[c.ip];
      const verified = c.internal || trusted || (!!c.ip && !!seenEndpoints[c.ip]);
      const unverified = !verified && !c.internal && c.direction === 'outbound';
      const risk = clamp(c.riskBase + (unverified ? 30 : 0) + (trusted ? -15 : 0), 0, 100);
      return { ...c, trusted, verified, unverified, risk };
    });

    conns.sort((a, b) => {
      if (b.risk !== a.risk) return b.risk - a.risk;
      if (a.direction !== b.direction) return a.direction === 'outbound' ? -1 : 1;
      return String(a.process).localeCompare(String(b.process));
    });

    const stats = {
      total: conns.length,
      outbound: conns.filter((c) => c.direction === 'outbound').length,
      inbound: conns.filter((c) => c.direction === 'inbound').length,
      listeners: conns.filter((c) => c.listener).length,
      exposed: conns.filter((c) => c.listener && c.exposed && c.encryption === 'plaintext').length,
      loopback: conns.filter((c) => c.direction === 'loopback').length,
      encrypted: conns.filter((c) => c.encryption === 'encrypted').length,
      plaintext: conns.filter((c) => c.encryption === 'plaintext').length,
      unknown: conns.filter((c) => c.encryption === 'unknown').length,
      unverified: conns.filter((c) => c.unverified).length,
      trusted: Object.keys(trustedIps).length,
      baselineEndpoints: Object.keys(seenEndpoints).length,
      alerts: this.feed.length,
      critical: this.feed.filter((a) => a.severity === 'critical').length
    };

    return {
      at: Date.now(),
      host: os.hostname(),
      platform: `${process.platform} ${os.release()}`,
      pollMs: this.pollMs,
      baselineAt: this.state.baselineAt,
      scanError: this.scanError,
      stats,
      connections: conns,
      alerts: this.feed.slice(0, MAX_FEED)
    };
  }

  /* --------------------------------------------------------------- actions */

  trust(ip) {
    if (!ip) return this.snapshot;
    this.state.trustedIps[ip] = Date.now();
    this.state.muted[`endpoint:${ip}`] = Date.now();
    this.feed = this.feed.filter((a) => a.ip !== ip);
    this.dirty = true;
    this.snapshot = this.buildSnapshot();
    return this.snapshot;
  }

  untrust(ip) {
    if (!ip) return this.snapshot;
    delete this.state.trustedIps[ip];
    this.dirty = true;
    this.snapshot = this.buildSnapshot();
    return this.snapshot;
  }

  acknowledge(key) {
    if (!key) return this.snapshot;
    this.state.muted[key] = Date.now();
    this.feed = this.feed.filter((a) => a.id !== key);
    this.dirty = true;
    this.snapshot = this.buildSnapshot();
    return this.snapshot;
  }

  clearFeed() {
    this.feed = [];
    this.dirty = true;
    this.snapshot = this.buildSnapshot();
    return this.snapshot;
  }

  baselineNow() {
    const now = Date.now();
    for (const c of this.lastConns) {
      if (c.listener) continue;
      if (!c.ip || c.ip === '*' || c.ip === '0.0.0.0' || c.ip === '::') continue;
      this.state.seenEndpoints[c.ip] = now;
      this.state.seenProcesses[c.process] = now;
    }
    this.state.baselineAt = now;
    this.feed = this.feed.filter((a) => a.type !== 'unverified-endpoint' && a.type !== 'unverified-process');
    this.feed.unshift({
      id: `system:${now}`,
      type: 'system',
      severity: 'info',
      title: 'Baseline refreshed',
      detail: `Everything currently visible is now treated as known (${Object.keys(this.state.seenEndpoints).length} endpoints).`,
      at: now
    });
    this.dirty = true;
    this.save();
    this.snapshot = this.buildSnapshot();
    return this.snapshot;
  }
}

module.exports = { Monitor };
