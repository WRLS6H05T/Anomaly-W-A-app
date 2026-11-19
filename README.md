# Anomaly Watch

A network monitor that watches live traffic and alerts you when it sees **unverified network activity** or **unencrypted data**. Two builds live in this repo:

| Build | What it watches | Where |
| --- | --- | --- |
| **Desktop** (`server.js`, `lib/`, `public/`) | This computer's sockets: endpoints, processes, listeners | `http://127.0.0.1:4177` |
| **Android** (`android/`) | The phone's networks and sockets, with background alerts | `dist/anomaly-watch-1.0.apk` |

Both share the same idea: learn what is normal for this device, then flag anything new, and flag anything that is not encrypted.

[![Download APK](https://img.shields.io/badge/download-anomaly--watch--1.3.apk-58A6FF?style=for-the-badge)](https://github.com/WRLS6H05T/Anomaly-W-A-app/raw/main/dist/anomaly-watch-1.3.apk)

**Direct download (right-click → Save link as, or just open it on the phone):**
<https://github.com/WRLS6H05T/Anomaly-W-A-app/raw/main/dist/anomaly-watch-1.3.apk>

> `anomaly-watch-1.3.apk` · signed · Android 8.0+ · package `com.wrls6h05t.anomalywatch`
> The file also lives in the repo at [`dist/anomaly-watch-1.3.apk`](https://github.com/WRLS6H05T/Anomaly-W-A-app/blob/main/dist/anomaly-watch-1.3.apk) — use its **Download** button if the raw link is blocked by your browser.
>
> **First run:** open the **Traffic** tab and tap the first row → enable Usage access for Anomaly Watch. Android does not report other apps' traffic without it, which is why the list can look empty.

---

## Android app

**Install:** sideload `dist/anomaly-watch-1.3.apk` (Android 8.0 or newer):

```bash
adb install dist/anomaly-watch-1.3.apk
```

or copy the APK to the phone and open it (allow installs from unknown sources once).

**What it does**

- Measures **per-app traffic** every 4 seconds through `NetworkStatsManager` — bytes up and down per UID over the last two minutes, resolved to an app name. This is the view that works on modern Android without root.
- Also tries the kernel socket table (`/proc/net/tcp{,6}`, `udp{,6}`) and shows those rows when the platform allows it.
- Fingerprints the network it is attached to (transport, SSID/interface, gateway, DNS servers, Private DNS, VPN, metered) and remembers the ones it has seen.
- Runs in a foreground service, so it keeps watching while the app is closed, and posts a notification for high/critical findings.
- Carries the same look as the desktop dashboard: identical palette, five stat cards with colour rails, segmented tabs, and alert cards with a severity rail, mono metadata and inline Trust/Dismiss actions.

**Alerts**

| Alert | Trigger |
| --- | --- |
| `unencrypted-traffic` | A plaintext protocol to a non-loopback peer (severity from the port table) |
| `exposed-service` | A high/critical plaintext service listening on all interfaces |
| `unverified-endpoint` | Outbound connection to an endpoint that is not in the baseline |
| `unverified-process` | An app or UID not in the baseline is using the network (socket-level, when readable) |
| `unverified-app` | An app not in the baseline transferred data in the last two minutes |
| `unverified-network` | The device joined a network it has never been on before |
| `unencrypted-network` | Wi-Fi/Ethernet with Private DNS off and no VPN — DNS queries leave in clear text |
| `system` | Informational: baseline established or refreshed |

Open the **Alerts** tab and tap a finding to **Dismiss** it or **Trust** its endpoint. **Re-baseline** accepts the current state as known. The **Traffic** tab lists each app with its download/upload bytes for the last two minutes (new apps in amber, known ones in blue) and appends any raw sockets the platform exposes; the **Network** tab shows the current network fingerprint and baseline sizes.

**Build it yourself** (no Gradle needed — the script drives aapt2, javac, d8, zipalign and apksigner directly):

```bash
bash android/build.sh        # writes ../dist/anomaly-watch-1.3.apk
```

Requires the Android SDK (build-tools 36.0.0, platform android-34) and any JDK. `android/release.keystore` signs the APK (alias and passwords: `anomalywatch`); keep it if you want later builds to install over this one.

**Android limitations, honestly**

- Android does not hand other apps' sockets to unprivileged apps, so per-app **byte counts** are the reliable signal. The raw socket list is usually just this app's own entries, and the app says so instead of inventing rows.
- The **TLS** and **PLAINTEXT** stat cards therefore read **—** / `blocked by OS` on stock Android: SELinux denies `/proc/net/tcp{,6}` (`avc: denied { read } … proc_net_tcp_udp`), so per-connection encryption cannot be counted. They show real counts only where the socket table is readable. Seeing ports on a phone needs a VPN-based capture, which is not implemented here.
- Per-app traffic requires **Usage access**, granted once in Settings (the Traffic tab links straight there). Until it is granted, only the network-level checks run.
- Encryption is judged from the port knowledge base, not from packet contents — a service on an unusual port reads as *unknown*.
- Open-Wi-Fi detection (WPA vs. open) needs location permission and a scan, so the app flags *unencrypted DNS* rather than the Wi-Fi cipher.
- The baseline is behavioural: whatever is already running or connected at first launch counts as known.

---

## Desktop app

Runs a small dashboard on `http://127.0.0.1:4177` with zero dependencies — just Node.js.

### Why local

The desktop build reads the operating system's own connection table, so it has to run on the machine it is watching. It binds `127.0.0.1` only; nothing leaves the host.

### Requirements

- Node.js 18 or newer (no `npm install` needed — no dependencies)
- Windows, macOS or Linux
  - Windows: uses `netstat -ano` and `tasklist`
  - macOS/Linux: uses `ss -tunapH`, falling back to `netstat -an`

### Run

```bash
node server.js
# or
npm start
```

Then open http://127.0.0.1:4177. Stop it with Ctrl+C.

### Configuration

| Variable           | Default     | Meaning                       |
| ------------------ | ----------- | ----------------------------- |
| `NETWATCH_PORT`    | `4177`      | HTTP port for the dashboard   |
| `NETWATCH_HOST`    | `127.0.0.1` | Interface to bind             |
| `NETWATCH_POLL_MS` | `2500`      | Scan interval in milliseconds |

### How detection works

Every scan is evaluated two ways.

**1. Verified vs unverified (behavioural baseline).** The first scan records every remote endpoint and process it can see into a baseline (`data/state.json`). From then on, a connection to an endpoint that was never in the baseline, or a process that was not, is reported as *unverified*. Trusting an endpoint adds it to an allow-list; dismissing an alert mutes that finding; **Re-baseline** treats everything currently visible as known.

**2. Encrypted vs unencrypted (port knowledge base).** Each port is classified as TLS, plaintext or unknown from a table of ~70 well-known service ports (`443`, `853`, `5223` → encrypted; `80`, `8080`, `21`, `23`, `143`, `5900` → plaintext). No packet capture is involved, so no admin rights, driver or Npcap is needed.

### Alerts

| Alert | Trigger | Severity |
| --- | --- | --- |
| `unencrypted-traffic` | A plaintext protocol is used to a non-loopback peer | port-dependent (low → critical) |
| `exposed-service` | A high/critical plaintext service is listening on all interfaces (`0.0.0.0` / `::`) | high / critical |
| `unverified-endpoint` | Outbound connection to an endpoint absent from the baseline | low (LAN) / medium (public) |
| `unverified-process` | A process not in the baseline is using the network | medium |
| `system` | Informational: baseline established or refreshed | info |

Alerts are deduplicated, persisted, and survive restarts until dismissed or cleared.

### Dashboard

- Live table: process, PID, protocol, state, endpoint, resolved host name, service, encryption, risk
- Filters: all / unencrypted / unverified / listening, plus free-text search
- **Trust** an endpoint (clears its alerts and suppresses future ones), **Untrust** to reverse it
- **Re-baseline** to accept the current state as known
- Pause/resume the live stream; updates arrive over Server-Sent Events

### HTTP API

| Route | Method | Purpose |
| --- | --- | --- |
| `/api/state` | GET | Current snapshot (stats, connections, alerts) |
| `/api/stream` | GET | SSE stream of snapshots every poll |
| `/api/trust` | POST `{ ip }` | Trust an endpoint |
| `/api/untrust` | POST `{ ip }` | Remove trust |
| `/api/ack` | POST `{ key }` | Dismiss one alert |
| `/api/alerts/clear` | POST | Clear the alert feed |
| `/api/baseline` | POST | Re-baseline from current state |

---

## Layout

```
server.js                    HTTP server, static files, SSE, actions
lib/collect.js               OS collection, parsing, process names, reverse DNS
lib/classify.js              port knowledge base, address helpers, severity ranking
lib/monitor.js               baseline learning, alert rules, persistence
public/                      desktop dashboard (HTML, CSS, JS)
data/state.json              desktop baseline, trust list, alerts (git-ignored)

android/AndroidManifest.xml  Android package, permissions, service
android/src/…/NetScan.java   /proc/net socket parsing, address decoding
android/src/…/NetInfo.java   network fingerprint (SSID, gateway, DNS, VPN)
android/src/…/Traffic.java   per-app traffic via NetworkStatsManager
android/src/…/Ports.java     shared port knowledge base
android/src/…/Monitor.java   baseline, alert rules, JSON persistence
android/src/…/WatchService.java  foreground service + notifications
android/src/…/MainActivity.java  dashboard UI
android/build.sh             Gradle-free APK build (aapt2 → javac → d8 → apksigner)
dist/anomaly-watch-1.3.apk   signed, installable Android build
```

## Limitations (both builds)

- Port-based encryption classification only — no payload inspection.
- The baseline is behavioural, not signature-based: anything already running at first launch counts as known, so re-baseline after a deliberate change in your habits.
- Desktop reverse DNS is best-effort and skipped for private addresses.
