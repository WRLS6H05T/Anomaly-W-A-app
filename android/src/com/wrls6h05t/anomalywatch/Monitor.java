package com.wrls6h05t.anomalywatch;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Baseline learning, alert rules and persistence. All public methods are synchronized. */
final class Monitor {

    static final int MAX_FEED = 120;
    private static final String PREFS = "anomaly_watch";
    private static final String KEY = "state";
    private static final int MAX_NOTIFIED = 3000;

    private static Monitor instance;

    static synchronized Monitor get(Context ctx) {
        if (instance == null) instance = new Monitor(ctx.getApplicationContext());
        return instance;
    }

    static final class Alert {
        String id = "";
        String type = "";
        String severity = "info";
        String title = "";
        String detail = "";
        String ip = "";
        long at;
    }

    static final class Conn {
        String id = "";
        String proto = "";
        String state = "";
        String process = "";
        String localIp = "";
        String remoteIp = "";
        String service = "";
        String encryption = "unknown";
        String severity = "";
        String why = "";
        int localPort;
        int remotePort;
        int uid;
        int risk;
        boolean listener;
        boolean inbound;
        boolean exposed;
        boolean trusted;
        boolean verified;
    }

    static final class Snapshot {
        List<Alert> alerts = new ArrayList<>();
        List<Conn> conns = new ArrayList<>();
        NetInfo net;
        int total;
        int unverified;
        int plaintext;
        int listeners;
        int exposed;
        long baselineAt;
        long updatedAt;
        String scanNote = "";
        int endpoints;
        int processes;
        int networks;
        int trustedCount;
    }

    private final Context ctx;
    private final SharedPreferences prefs;

    private long baselineAt;
    private long updatedAt;
    private String scanNote = "";

    private final Map<String, Long> endpoints = new HashMap<>();
    private final Map<String, Long> processes = new HashMap<>();
    private final Map<String, Long> networks = new HashMap<>();
    private final Map<String, Long> trusted = new HashMap<>();
    private final Map<String, Long> muted = new HashMap<>();
    private final Map<String, Long> notified = new HashMap<>();
    private final Map<Integer, String> uidNames = new HashMap<>();
    private final List<Alert> feed = new ArrayList<>();
    private final List<Alert> fresh = new ArrayList<>();

    private List<Conn> conns = new ArrayList<>();
    private NetInfo net;

    private Monitor(Context ctx) {
        this.ctx = ctx;
        this.prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        load();
    }

    /* --------------------------------------------------------------- scanning */

    synchronized void tick() {
        NetInfo info = NetInfo.snapshot(ctx);
        NetScan.Result scan = NetScan.read();
        long now = System.currentTimeMillis();
        boolean firstPass = baselineAt == 0;

        scanNote = scan.error == null ? "" : scan.error;

        List<Conn> built = new ArrayList<>();
        List<Alert> candidates = new ArrayList<>();

        Set<Integer> listenerPorts = new HashSet<>();
        for (NetScan.Sock s : scan.socks) {
            if (s.listener) listenerPorts.add(s.localPort);
        }

        for (NetScan.Sock s : scan.socks) {
            boolean remoteLoopback = !s.listener && Ports.isLoopback(s.remoteIp);
            boolean loopback = !s.listener && (remoteLoopback || Ports.isLoopback(s.localIp));
            Ports.Info pi = Ports.classify(s.listener ? s.localPort : s.remotePort, s.proto);
            boolean exposed = s.listener && ("0.0.0.0".equals(s.localIp)
                    || "::".equals(s.localIp) || "*".equals(s.localIp)
                    || "0:0:0:0:0:0:0:0".equals(s.localIp));
            boolean inbound = !s.listener && listenerPorts.contains(s.localPort) && !remoteLoopback;
            String ip = s.listener ? s.localIp : s.remoteIp;
            String process = nameForUid(s.uid);
            boolean isTrusted = ip != null && trusted.containsKey(ip);
            boolean internal = s.listener || loopback;
            boolean verified = internal || isTrusted || (ip != null && endpoints.containsKey(ip));

            int risk = 0;
            if ("plaintext".equals(pi.mode)) {
                if (s.listener) risk = exposed ? 45 + pi.rank * 10 : 0;
                else if (!remoteLoopback) risk = 50 + pi.rank * 10;
            }
            if (!verified && !internal) risk += 30;
            if (isTrusted) risk -= 15;
            risk = Math.max(0, Math.min(100, risk));

            Conn c = new Conn();
            c.id = s.id();
            c.proto = s.proto;
            c.state = s.state;
            c.process = process;
            c.localIp = s.localIp;
            c.remoteIp = s.remoteIp;
            c.localPort = s.localPort;
            c.remotePort = s.remotePort;
            c.uid = s.uid;
            c.listener = s.listener;
            c.inbound = inbound;
            c.exposed = exposed;
            c.trusted = isTrusted;
            c.verified = verified;
            c.service = pi.service;
            c.encryption = pi.mode;
            c.severity = pi.severity == null ? "" : pi.severity;
            c.why = pi.why;
            c.risk = risk;
            built.add(c);

            if ("plaintext".equals(pi.mode) && pi.severity != null) {
                if (s.listener) {
                    if (exposed && ("high".equals(pi.severity) || "critical".equals(pi.severity))) {
                        candidates.add(alert("exposure:" + s.localIp + ":" + s.localPort + ":" + process,
                                "exposed-service", pi.severity,
                                "Unencrypted " + pi.service + " listening on all interfaces",
                                process + " is listening on " + s.localIp + ":" + s.localPort
                                        + " without encryption. " + pi.why, ""));
                    }
                } else if (!remoteLoopback) {
                    candidates.add(alert("plaintext:" + ip + ":" + s.remotePort + ":" + pi.service,
                            "unencrypted-traffic", pi.severity,
                            "Unencrypted " + pi.service + " traffic",
                            process + " → " + ip + ":" + s.remotePort + ". " + pi.why, ip));
                }
            }

            if (!internal && !isTrusted) {
                if (ip != null && !endpoints.containsKey(ip)) {
                    candidates.add(alert("endpoint:" + ip, "unverified-endpoint",
                            Ports.isPrivateIp(ip) ? "low" : "medium",
                            "Unverified remote endpoint contacted",
                            process + " opened " + s.proto.toUpperCase() + " " + ip + ":" + s.remotePort
                                    + " (" + pi.service + ") — never seen in the baseline.", ip));
                }
                if (!processes.containsKey(process)) {
                    candidates.add(alert("process:" + process, "unverified-process", "medium",
                            "Unverified process using the network",
                            process + " (uid " + s.uid + ") is talking to " + ip + ":" + s.remotePort
                                    + " and is not part of the baseline.", ip));
                }
            }
        }

        if (info != null && info.fingerprint != null && !info.fingerprint.isEmpty()) {
            if (!firstPass && !networks.containsKey(info.fingerprint)) {
                candidates.add(alert("network:" + info.fingerprint, "unverified-network", "medium",
                        "Unverified network: " + info.label(),
                        "This device is attached to " + info.describe()
                                + ", which is not in the baseline.", ""));
            }
            if (!firstPass && !info.vpn && "off".equals(info.privateDns) && info.hasDns()) {
                candidates.add(alert("dns:" + info.fingerprint, "unencrypted-network", "medium",
                        "DNS lookups are not encrypted here",
                        "On " + info.label() + ": Private DNS is off and no VPN is active, so name lookups"
                                + " leave the device in clear text to " + info.dns + ".", ""));
            }
        }

        if (firstPass) {
            for (Conn c : built) {
                if (c.listener) continue;
                if (isRemote(c.remoteIp)) endpoints.put(c.remoteIp, now);
                processes.put(c.process, now);
            }
            if (info != null && info.fingerprint != null && !info.fingerprint.isEmpty()) {
                networks.put(info.fingerprint, now);
            }
            baselineAt = now;
            feed.add(0, alert("system:" + now, "system", "info", "Baseline established",
                    "Recorded " + endpoints.size() + " endpoints, " + processes.size() + " processes and "
                            + networks.size() + " network(s). Anything new from here on is reported as unverified.",
                    ""));
        } else {
            for (Alert a : candidates) {
                if (muted.containsKey(a.id) || notified.containsKey(a.id)) continue;
                notified.put(a.id, now);
                feed.add(0, a);
                fresh.add(a);
            }
        }

        for (Conn c : built) {
            if (c.listener) continue;
            if (isRemote(c.remoteIp) && !endpoints.containsKey(c.remoteIp)) endpoints.put(c.remoteIp, now);
            if (!processes.containsKey(c.process)) processes.put(c.process, now);
        }
        if (info != null && info.fingerprint != null && !info.fingerprint.isEmpty()
                && !networks.containsKey(info.fingerprint)) {
            networks.put(info.fingerprint, now);
        }

        while (feed.size() > MAX_FEED) feed.remove(feed.size() - 1);
        if (notified.size() > MAX_NOTIFIED) notified.clear();

        conns = built;
        net = info;
        updatedAt = now;
        save();
    }

    private static boolean isRemote(String ip) {
        return ip != null && !ip.isEmpty() && !"*".equals(ip)
                && !"0.0.0.0".equals(ip) && !"::".equals(ip) && !"0:0:0:0:0:0:0:0".equals(ip);
    }

    private static Alert alert(String id, String type, String severity, String title, String detail, String ip) {
        Alert a = new Alert();
        a.id = id;
        a.type = type;
        a.severity = severity;
        a.title = title;
        a.detail = detail;
        a.ip = ip == null ? "" : ip;
        a.at = System.currentTimeMillis();
        return a;
    }

    private String nameForUid(int uid) {
        String cached = uidNames.get(uid);
        if (cached != null) return cached;
        String name;
        if (uid == 0) {
            name = "root";
        } else if (uid == 1000) {
            name = "android (system)";
        } else {
            try {
                String[] pkgs = ctx.getPackageManager().getPackagesForUid(uid);
                name = (pkgs != null && pkgs.length > 0) ? pkgs[0] : "uid " + uid;
            } catch (Exception e) {
                name = "uid " + uid;
            }
        }
        if (uidNames.size() > 500) uidNames.clear();
        uidNames.put(uid, name);
        return name;
    }

    /* ------------------------------------------------------------------- view */

    synchronized Snapshot snapshot() {
        Snapshot s = new Snapshot();
        s.alerts = new ArrayList<>(feed);
        s.conns = new ArrayList<>(conns);
        s.net = net;
        s.baselineAt = baselineAt;
        s.updatedAt = updatedAt;
        s.scanNote = scanNote;
        s.endpoints = endpoints.size();
        s.processes = processes.size();
        s.networks = networks.size();
        s.trustedCount = trusted.size();
        for (Conn c : s.conns) {
            s.total++;
            if (!c.verified && !c.listener) s.unverified++;
            if ("plaintext".equals(c.encryption)) s.plaintext++;
            if (c.listener) {
                s.listeners++;
                if (c.exposed) s.exposed++;
            }
        }
        return s;
    }

    synchronized List<Alert> drainNewAlerts() {
        List<Alert> out = new ArrayList<>(fresh);
        fresh.clear();
        return out;
    }

    /* ---------------------------------------------------------------- actions */

    synchronized void trust(String ip) {
        if (ip == null || ip.isEmpty()) return;
        long now = System.currentTimeMillis();
        trusted.put(ip, now);
        muted.put("endpoint:" + ip, now);
        Iterator<Alert> it = feed.iterator();
        while (it.hasNext()) {
            Alert a = it.next();
            if (ip.equals(a.ip)) it.remove();
        }
        save();
    }

    synchronized void untrust(String ip) {
        if (ip == null || ip.isEmpty()) return;
        trusted.remove(ip);
        muted.remove("endpoint:" + ip);
        save();
    }

    synchronized void dismiss(String id) {
        if (id == null || id.isEmpty()) return;
        muted.put(id, System.currentTimeMillis());
        Iterator<Alert> it = feed.iterator();
        while (it.hasNext()) {
            if (id.equals(it.next().id)) it.remove();
        }
        save();
    }

    synchronized void clearFeed() {
        feed.clear();
        save();
    }

    synchronized void baselineNow() {
        long now = System.currentTimeMillis();
        for (Conn c : conns) {
            if (c.listener) continue;
            if (isRemote(c.remoteIp)) endpoints.put(c.remoteIp, now);
            processes.put(c.process, now);
        }
        if (net != null && net.fingerprint != null && !net.fingerprint.isEmpty()) {
            networks.put(net.fingerprint, now);
        }
        baselineAt = now;
        Iterator<Alert> it = feed.iterator();
        while (it.hasNext()) {
            String type = it.next().type;
            if ("unverified-endpoint".equals(type) || "unverified-process".equals(type)
                    || "unverified-network".equals(type)) {
                it.remove();
            }
        }
        feed.add(0, alert("system:" + now, "system", "info", "Baseline refreshed",
                "Everything currently visible is now treated as known (" + endpoints.size()
                        + " endpoints, " + networks.size() + " network(s)).", ""));
        save();
    }

    /* ------------------------------------------------------------ persistence */

    private void load() {
        String raw = prefs.getString(KEY, null);
        if (raw == null) return;
        try {
            JSONObject o = new JSONObject(raw);
            baselineAt = o.optLong("baselineAt", 0);
            readMap(o.optJSONObject("endpoints"), endpoints);
            readMap(o.optJSONObject("processes"), processes);
            readMap(o.optJSONObject("networks"), networks);
            readMap(o.optJSONObject("trusted"), trusted);
            readMap(o.optJSONObject("muted"), muted);
            JSONArray f = o.optJSONArray("feed");
            if (f != null) {
                for (int i = 0; i < f.length() && i < MAX_FEED; i++) {
                    JSONObject a = f.getJSONObject(i);
                    Alert al = new Alert();
                    al.id = a.optString("id");
                    al.type = a.optString("type");
                    al.severity = a.optString("severity", "info");
                    al.title = a.optString("title");
                    al.detail = a.optString("detail");
                    al.ip = a.optString("ip");
                    al.at = a.optLong("at");
                    feed.add(al);
                }
            }
        } catch (Exception ignored) {
            // corrupt state: start from an empty baseline
        }
    }

    private void save() {
        try {
            JSONObject o = new JSONObject();
            o.put("baselineAt", baselineAt);
            o.put("endpoints", writeMap(endpoints));
            o.put("processes", writeMap(processes));
            o.put("networks", writeMap(networks));
            o.put("trusted", writeMap(trusted));
            o.put("muted", writeMap(muted));
            JSONArray f = new JSONArray();
            for (Alert a : feed) {
                JSONObject x = new JSONObject();
                x.put("id", a.id);
                x.put("type", a.type);
                x.put("severity", a.severity);
                x.put("title", a.title);
                x.put("detail", a.detail);
                x.put("ip", a.ip);
                x.put("at", a.at);
                f.put(x);
            }
            o.put("feed", f);
            prefs.edit().putString(KEY, o.toString()).apply();
        } catch (Exception ignored) {
            // never let a storage problem stop monitoring
        }
    }

    private static void readMap(JSONObject src, Map<String, Long> dst) {
        if (src == null) return;
        Iterator<String> keys = src.keys();
        while (keys.hasNext()) {
            String k = keys.next();
            dst.put(k, src.optLong(k, 0));
        }
    }

    private static JSONObject writeMap(Map<String, Long> map) {
        JSONObject o = new JSONObject();
        for (Map.Entry<String, Long> e : map.entrySet()) {
            try {
                o.put(e.getKey(), e.getValue());
            } catch (Exception ignored) {
                // skip unencodable key
            }
        }
        return o;
    }
}
