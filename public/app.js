'use strict';

const ui = {
  data: null,
  filter: 'all',
  search: '',
  paused: false,
  es: null
};

const el = {
  stats: document.getElementById('stats'),
  rows: document.getElementById('rows'),
  connCount: document.getElementById('connCount'),
  connFoot: document.getElementById('connFoot'),
  emptyConns: document.getElementById('emptyConns'),
  alertList: document.getElementById('alertList'),
  alertCount: document.getElementById('alertCount'),
  emptyAlerts: document.getElementById('emptyAlerts'),
  livePill: document.getElementById('livePill'),
  liveLabel: document.getElementById('liveLabel'),
  hostLabel: document.getElementById('hostLabel'),
  baselineLabel: document.getElementById('baselineLabel'),
  pollLabel: document.getElementById('pollLabel'),
  scanNote: document.getElementById('scanNote'),
  toggleBtn: document.getElementById('toggleBtn'),
  baselineBtn: document.getElementById('baselineBtn'),
  clearBtn: document.getElementById('clearBtn'),
  search: document.getElementById('search'),
  tabs: document.getElementById('tabs'),
  tableWrap: document.querySelector('.table-wrap')
};

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ESC[c]);

function timeAgo(ts) {
  if (!ts) return 'never';
  const diff = Math.max(0, Date.now() - ts);
  const sec = Math.round(diff / 1000);
  if (sec < 10) return 'just now';
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.round(hr / 24)}d ago`;
}

function clock(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour12: false });
}

function riskTier(risk) {
  if (risk >= 70) return 'critical';
  if (risk >= 50) return 'high';
  if (risk >= 28) return 'medium';
  if (risk > 8) return 'low';
  return 'none';
}

function riskLabel(risk) {
  const tier = riskTier(risk);
  return tier === 'none' ? 'clean' : tier;
}

function directionLabel(c) {
  if (c.listener) return c.exposed ? 'listening · exposed' : 'listening · local';
  if (c.inbound) return 'inbound';
  if (c.direction === 'loopback') return 'loopback';
  return 'outbound';
}

/* -------------------------------------------------------------------- stats */

function renderStats() {
  const s = ui.data.stats;
  const cards = [
    {
      cls: 'neutral',
      label: 'Active connections',
      value: s.total,
      sub: `${s.outbound} outbound · ${s.listeners} listening`
    },
    { cls: 'enc', label: 'Encrypted', value: s.encrypted, sub: 'TLS / QUIC sessions' },
    { cls: 'plain', label: 'Unencrypted', value: s.plaintext, sub: `${s.unknown} unclassified ports` },
    { cls: 'unv', label: 'Unverified', value: s.unverified, sub: `${s.trusted} trusted endpoints` },
    {
      cls: 'alert',
      label: 'Open alerts',
      value: s.alerts,
      sub: `${s.critical} critical · ${s.exposed} exposed listeners`
    }
  ];
  el.stats.innerHTML = cards
    .map(
      (card) => `
      <div class="stat ${card.cls}">
        <span class="stat-label">${esc(card.label)}</span>
        <span class="stat-value">${card.value}</span>
        <span class="stat-sub">${esc(card.sub)}</span>
      </div>`
    )
    .join('');
}

/* -------------------------------------------------------------- connections */

function matchesFilter(c) {
  if (ui.filter === 'plaintext' && c.encryption !== 'plaintext') return false;
  if (ui.filter === 'unverified' && !c.unverified) return false;
  if (ui.filter === 'listener' && !c.listener) return false;
  if (!ui.search) return true;
  const q = ui.search.toLowerCase();
  return [c.process, c.ip, c.hostname, c.service, c.remote.port, c.local.port, c.pid]
    .filter((v) => v !== null && v !== undefined)
    .some((v) => String(v).toLowerCase().includes(q));
}

function encryptionBadge(c) {
  if (c.encryption === 'encrypted') return '<span class="badge enc">TLS</span>';
  if (c.encryption === 'plaintext') return '<span class="badge plain">NO TLS</span>';
  return '<span class="badge unk">unknown</span>';
}

function trustBadge(c) {
  if (c.listener) return '<span class="badge dir">listening</span>';
  if (c.internal) return '<span class="badge local">local</span>';
  if (c.trusted) return '<span class="badge ok">trusted</span>';
  if (c.unverified) return '<span class="badge unv">unverified</span>';
  return '<span class="badge ok">known</span>';
}

function endpointCell(c) {
  if (c.listener) {
    return `<span class="ip">${esc(c.local.host)}:${c.local.port}</span>
      <span class="host">${esc(directionLabel(c))}</span>`;
  }
  const arrow = c.inbound ? '←' : '→';
  const host = c.hostname ? esc(c.hostname) : c.ip ? 'no PTR record' : '—';
  return `<span class="ip">${arrow} ${esc(c.ip || c.remote.host)}:${c.remote.port}</span>
    <span class="host">${host}</span>`;
}

function renderConnections() {
  const all = ui.data.connections;
  const visible = all.filter(matchesFilter).slice(0, 400);
  const wrap = el.tableWrap;
  const scrollTop = wrap ? wrap.scrollTop : 0;

  el.rows.innerHTML = visible
    .map((c) => {
      const tier = riskTier(c.risk);
      const rowClass = tier === 'critical' || tier === 'high' ? 'risk-high' : tier === 'medium' ? 'risk-med' : '';
      const action =
        c.ip && !c.internal
          ? c.trusted
            ? `<button class="mini" type="button" data-act="untrust" data-ip="${esc(c.ip)}">Untrust</button>`
            : `<button class="mini primary" type="button" data-act="trust" data-ip="${esc(c.ip)}">Trust</button>`
          : '';
      return `<tr class="${rowClass}" title="${esc(c.why || '')}">
        <td>
          <div class="proc">
            <span class="pname">${esc(c.process)}</span>
            <span class="pid">pid ${esc(c.pid)} · ${esc(c.proto.toUpperCase())} ${esc(c.state)}</span>
          </div>
        </td>
        <td>${endpointCell(c)}</td>
        <td><span class="svc">${esc(c.service)}</span></td>
        <td>${encryptionBadge(c)}</td>
        <td>${trustBadge(c)}</td>
        <td class="right"><span class="risk ${tier}">${esc(riskLabel(c.risk))}</span></td>
        <td class="right">${action}</td>
      </tr>`;
    })
    .join('');

  el.emptyConns.hidden = visible.length > 0;
  el.connCount.textContent = String(all.length);

  const s = ui.data.stats;
  el.connFoot.textContent = `showing ${visible.length} of ${all.length} · ${s.plaintext} unencrypted · ${s.unverified} unverified · baseline ${timeAgo(
    ui.data.baselineAt
  )}`;

  if (wrap) wrap.scrollTop = scrollTop;
}

/* ------------------------------------------------------------------- alerts */

function renderAlerts() {
  const alerts = ui.data.alerts;
  el.alertCount.textContent = String(alerts.length);
  el.emptyAlerts.hidden = alerts.length > 0;

  el.alertList.innerHTML = alerts
    .map((a) => {
      const actions = [];
      if (a.ip && a.type !== 'system') {
        actions.push(
          `<button class="mini primary" type="button" data-act="trust" data-ip="${esc(a.ip)}">Trust ${
            a.ip.length > 22 ? 'endpoint' : esc(a.ip)
          }</button>`
        );
      }
      if (a.type !== 'system') {
        actions.push(`<button class="mini" type="button" data-act="dismiss" data-key="${esc(a.id)}">Dismiss</button>`);
      }
      return `<article class="alert ${esc(a.severity)}">
        <div class="alert-top">
          <span class="sev">${esc(a.severity)}</span>
          <span class="time">${clock(a.at)}</span>
        </div>
        <h3>${esc(a.title)}</h3>
        <p>${esc(a.detail)}</p>
        ${actions.length ? `<div class="alert-actions">${actions.join('')}</div>` : ''}
      </article>`;
    })
    .join('');
}

/* -------------------------------------------------------------------- shell */

function renderStatus() {
  const d = ui.data;
  el.hostLabel.textContent = `${d.host} · ${d.platform}`;
  el.baselineLabel.textContent = d.baselineAt ? `baseline ${timeAgo(d.baselineAt)}` : 'no baseline yet';
  el.pollLabel.textContent = `${(d.pollMs / 1000).toFixed(1)}s`;
  el.scanNote.textContent = d.scanError ? `scan error: ${d.scanError}` : '';

  el.livePill.classList.toggle('paused', ui.paused);
  el.livePill.classList.toggle('error', !ui.paused && !!d.scanError);
  el.liveLabel.textContent = ui.paused ? 'paused' : d.scanError ? 'degraded' : 'live';
  el.toggleBtn.textContent = ui.paused ? 'Resume' : 'Pause';
}

function render() {
  if (!ui.data) return;
  renderStatus();
  renderStats();
  renderConnections();
  renderAlerts();
}

function apply(data) {
  ui.data = data;
  render();
}

/* --------------------------------------------------------------------- api */

async function post(path, body) {
  try {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    apply(await res.json());
  } catch (err) {
    el.scanNote.textContent = `request failed: ${err.message}`;
  }
}

function connect() {
  if (ui.es) ui.es.close();
  const es = new EventSource('/api/stream');
  ui.es = es;
  es.onmessage = (event) => {
    try {
      apply(JSON.parse(event.data));
    } catch {
      /* ignore malformed frame */
    }
  };
  es.onerror = () => {
    el.livePill.classList.add('error');
    el.liveLabel.textContent = 'reconnecting';
  };
}

async function refreshOnce() {
  const res = await fetch('/api/state');
  if (res.ok) apply(await res.json());
}

/* ------------------------------------------------------------------ events */

document.getElementById('rows').addEventListener('click', (event) => {
  const btn = event.target.closest('button[data-act]');
  if (!btn) return;
  const ip = btn.dataset.ip;
  if (btn.dataset.act === 'trust') post('/api/trust', { ip });
  if (btn.dataset.act === 'untrust') post('/api/untrust', { ip });
});

el.alertList.addEventListener('click', (event) => {
  const btn = event.target.closest('button[data-act]');
  if (!btn) return;
  if (btn.dataset.act === 'trust') post('/api/trust', { ip: btn.dataset.ip });
  if (btn.dataset.act === 'dismiss') post('/api/ack', { key: btn.dataset.key });
});

el.tabs.addEventListener('click', (event) => {
  const tab = event.target.closest('.tab');
  if (!tab) return;
  ui.filter = tab.dataset.filter;
  for (const t of el.tabs.querySelectorAll('.tab')) t.classList.toggle('active', t === tab);
  renderConnections();
});

el.search.addEventListener('input', (event) => {
  ui.search = event.target.value.trim();
  renderConnections();
});

el.toggleBtn.addEventListener('click', () => {
  ui.paused = !ui.paused;
  if (ui.paused) {
    if (ui.es) ui.es.close();
    ui.es = null;
    refreshOnce().catch(() => {});
  } else {
    connect();
  }
  renderStatus();
});

el.baselineBtn.addEventListener('click', () => post('/api/baseline'));
el.clearBtn.addEventListener('click', () => post('/api/alerts/clear'));

connect();
