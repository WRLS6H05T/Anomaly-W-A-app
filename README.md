# Netwatch

A local network monitor that watches the machine's live connections and alerts you when it sees **unverified network activity** or **unencrypted data**.

Runs as a small dashboard on `http://127.0.0.1:4177` with zero dependencies — just Node.js.

## Why local

Netwatch reads the operating system's own connection table, so it has to run on the machine it is watching. There is no server component, no telemetry, and nothing leaves the host: it binds `127.0.0.1` only. It is a desktop tool, not a hosted or mobile app.

## Requirements

- Node.js 18 or newer (no npm install needed — there are no dependencies)
- Windows, macOS or Linux
  - Windows: uses `netstat -ano` and `tasklist`
  - macOS/Linux: uses `ss -tunapH`, falling back to `netstat -an`

## Run

```bash
node server.js
# or
npm start
```

Then open http://127.0.0.1:4177. Stop it with Ctrl+C.

### Configuration

| Variable         | Default     | Meaning                        |
| ---------------- | ----------- | ------------------------------ |
| `NETWATCH_PORT`  | `4177`      | HTTP port for the dashboard    |
| `NETWATCH_HOST`  | `127.0.0.1` | Interface to bind              |
| `NETWATCH_POLL_MS` | `2500`    | Scan interval in milliseconds  |

## How detection works

Every scan is evaluated two ways.

**1. Verified vs unverified (behavioral baseline).**
The first scan records every remote endpoint and process it can see into a baseline (`data/state.json`). From then on, a connection to an endpoint that was never in the baseline, or a process that was not in the baseline, is reported as *unverified*. Trusting an endpoint adds it to an explicit allow-list; dismissing an alert mutes that specific finding; **Re-baseline** treats everything currently visible as known.

**2. Encrypted vs unencrypted (port knowledge base).**
Each port is classified as TLS/encrypted, plaintext, or unknown using a built-in table of ~70 well-known service ports (`443`, `853`, `5223` → encrypted; `80`, `8080`, `21`, `23`, `143`, `5900` → plaintext, and so on). No packet capture is involved, so no admin rights, driver or Npcap install is required — the trade-off is that a service tunnelled over an unusual port may read as *unknown* rather than encrypted.

## Alerts

| Alert | Trigger | Severity |
| --- | --- | --- |
| `unencrypted-traffic` | A plaintext protocol is used to a non-loopback peer | port-dependent (low → critical) |
| `exposed-service` | A high/critical plaintext service is listening on all interfaces (`0.0.0.0` / `::`) | high / critical |
| `unverified-endpoint` | Outbound connection to an endpoint absent from the baseline | low (LAN) / medium (public) |
| `unverified-process` | A process not in the baseline is using the network | medium |
| `system` | Informational: baseline established or refreshed | info |

Alerts are deduplicated, persisted, and survive restarts until dismissed or cleared.

## Dashboard

- Live table of connections: process, PID, protocol, state, endpoint, resolved host name, service, encryption and risk score
- Filters: all / unencrypted / unverified / listening, plus free-text search
- **Trust** an endpoint (clears its alerts, suppresses future ones), **Untrust** to reverse it
- **Re-baseline** to accept the current state as known
- Pause/resume the live stream; updates arrive over Server-Sent Events

## HTTP API

| Route | Method | Purpose |
| --- | --- | --- |
| `/api/state` | GET | Current snapshot (stats, connections, alerts) |
| `/api/stream` | GET | SSE stream of snapshots every poll |
| `/api/trust` | POST `{ ip }` | Trust an endpoint |
| `/api/untrust` | POST `{ ip }` | Remove trust |
| `/api/ack` | POST `{ key }` | Dismiss one alert |
| `/api/alerts/clear` | POST | Clear the alert feed |
| `/api/baseline` | POST | Re-baseline from current state |

## Files

```
server.js          HTTP server, static files, SSE, action routes
lib/collect.js     OS collection, parsing, process names, reverse DNS
lib/classify.js    port knowledge base, address helpers, severity ranking
lib/monitor.js     baseline learning, alert rules, persistence, snapshots
public/            dashboard (index.html, styles.css, app.js)
data/state.json    baseline, trust list, alerts (created at runtime, git-ignored)
```

## Limitations

- Port-based encryption classification only — it does not inspect payloads.
- The baseline is behavioural, not signature-based: anything already running on first launch counts as known. Re-baseline after a deliberate change in your network habits.
- Reverse DNS is best-effort and skipped for private addresses; missing PTR records show as "no PTR record".
- DNS lookups and scans can be slow on large tables; the scan interval is 2.5s by default.
