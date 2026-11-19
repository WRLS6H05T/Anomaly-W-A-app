package com.wrls6h05t.anomalywatch;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {

    /* palette — same tokens as public/styles.css */
    private static final int REQ_VPN = 77;

    private static final int BG = 0xFF05080D;
    private static final int PANEL_TOP = 0xFF0D141D;
    private static final int PANEL_BOT = 0xFF080D14;
    private static final int LINE = 0xFF182534;
    private static final int LINE_SOFT = 0xFF121C28;
    private static final int TEXT = 0xFFD8E3F1;
    private static final int TITLE = 0xFFE2ECF8;
    private static final int MUTED = 0xFF6C7F97;
    private static final int MUTED_2 = 0xFF4A5B70;
    private static final int ENC = 0xFF2EE6A8;
    private static final int PLAIN = 0xFFFF5F6D;
    private static final int WARN = 0xFFFFB545;
    private static final int CRIT = 0xFFFF3D5A;
    private static final int UNK = 0xFF8B9CB3;
    private static final int ACCENT = 0xFF59D6FF;
    private static final int NEUTRAL = 0xFF9FB3C8;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat clock = new SimpleDateFormat("HH:mm:ss", Locale.US);

    private Monitor monitor;
    private ListView list;
    private RowsAdapter adapter;
    private TextView liveLabel;
    private LinearLayout liveBox;
    private TextView metaLine;
    private TextView panelTitle;
    private TextView panelCount;
    private TextView panelHint;
    private TextView panelFoot;
    private TextView footNote;
    private TextView watchBtn;
    private final TextView[] statValues = new TextView[5];
    private final TextView[] statSubs = new TextView[5];
    private final TextView[] tabs = new TextView[3];
    private int tab;
    private long lastStamp = -1;

    private final Runnable refreshLoop = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 1500);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        monitor = Monitor.get(this);
        if (Build.VERSION.SDK_INT >= 21) getWindow().setStatusBarColor(BG);
        buildUi();
        startWatch();
        askForNotifications();
        handler.post(refreshLoop);
    }

    @Override
    protected void onDestroy() {
        handler.removeCallbacks(refreshLoop);
        super.onDestroy();
    }

    @Override
    protected void onResume() {
        super.onResume();
        maybeResumeCapture();
    }

    /** Re-arms the capture on launch once the tunnel has been approved; Stop opts out. */
    private void maybeResumeCapture() {
        if (DnsVpnService.RUNNING) return;
        if (getSharedPreferences("aw", MODE_PRIVATE).getBoolean("dns_stopped", false)) return;
        try {
            if (VpnService.prepare(this) == null) launchCapture();
        } catch (Exception ignored) {
            // VPN unavailable on this device
        }
    }

    /* ------------------------------------------------------------------ shell */

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setPadding(dp(12), dp(12), dp(12), dp(8));

        root.addView(topbar());
        root.addView(statsRow());

        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setBackground(panelBg(12));
        LinearLayout.LayoutParams panelLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        panelLp.topMargin = dp(10);
        panel.setLayoutParams(panelLp);
        panel.addView(panelHead());
        panel.addView(tabRow());

        list = new ListView(this);
        list.setBackgroundColor(Color.TRANSPARENT);
        list.setDivider(null);
        list.setSelector(android.R.color.transparent);
        list.setVerticalScrollBarEnabled(false);
        list.setPadding(dp(8), dp(8), dp(8), dp(8));
        list.setClipToPadding(false);
        list.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        adapter = new RowsAdapter();
        list.setAdapter(adapter);
        panel.addView(list);

        panelFoot = text("", 9.5f, MUTED_2, false);
        panelFoot.setTypeface(Typeface.MONOSPACE);
        panelFoot.setPadding(dp(14), dp(9), dp(14), dp(9));
        panelFoot.setBackground(topStroke());
        panel.addView(panelFoot);

        root.addView(panel);
        root.addView(footbar());

        setContentView(root);
    }

    private View topbar() {
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.VERTICAL);
        bar.setBackground(topbarBg());
        bar.setPadding(dp(13), dp(11), dp(13), dp(11));

        LinearLayout line1 = new LinearLayout(this);
        line1.setOrientation(LinearLayout.HORIZONTAL);
        line1.setGravity(Gravity.CENTER_VERTICAL);

        ImageView mark = new ImageView(this);
        mark.setImageResource(R.drawable.ic_launcher);
        mark.setLayoutParams(new LinearLayout.LayoutParams(dp(26), dp(26)));
        line1.addView(mark);

        LinearLayout brand = new LinearLayout(this);
        brand.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams brandLp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        brandLp.leftMargin = dp(10);
        brand.setLayoutParams(brandLp);

        TextView name = text("NETWATCH", 13.5f, TEXT, true);
        name.setLetterSpacing(0.26f);
        TextView tagline = text("Network activity & encryption monitor", 10f, MUTED, false);
        tagline.setPadding(0, dp(2), 0, 0);
        brand.addView(name);
        brand.addView(tagline);
        line1.addView(brand);

        liveBox = new LinearLayout(this);
        liveBox.setOrientation(LinearLayout.HORIZONTAL);
        liveBox.setGravity(Gravity.CENTER_VERTICAL);
        liveBox.setPadding(dp(9), dp(4), dp(9), dp(4));
        liveBox.setBackground(pillBg(ENC));
        View dot = new View(this);
        GradientDrawable dotBg = new GradientDrawable();
        dotBg.setShape(GradientDrawable.OVAL);
        dotBg.setColor(ENC);
        dot.setBackground(dotBg);
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dp(6), dp(6));
        dotLp.rightMargin = dp(6);
        dot.setLayoutParams(dotLp);
        liveBox.addView(dot);
        liveLabel = text("LIVE", 9f, ENC, true);
        liveLabel.setLetterSpacing(0.12f);
        liveBox.addView(liveLabel);
        line1.addView(liveBox);
        bar.addView(line1);

        metaLine = text("", 9.5f, MUTED, false);
        metaLine.setTypeface(Typeface.MONOSPACE);
        metaLine.setPadding(0, dp(8), 0, 0);
        bar.addView(metaLine);

        LinearLayout controls = new LinearLayout(this);
        controls.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams controlsLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        controlsLp.topMargin = dp(9);
        controls.setLayoutParams(controlsLp);

        controls.addView(chromeButton("Re-baseline", false, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                monitor.baselineNow();
                refresh();
            }
        }));
        controls.addView(chromeButton("Clear alerts", true, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                monitor.clearFeed();
                refresh();
            }
        }));
        watchBtn = chromeButton("Stop", false, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (WatchService.RUNNING) {
                    stopService(new Intent(MainActivity.this, WatchService.class));
                    stopService(new Intent(MainActivity.this, DnsVpnService.class));
                } else {
                    startWatch();
                }
                refresh();
            }
        });
        controls.addView(watchBtn);
        bar.addView(controls);
        return bar;
    }

    private View statsRow() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(10);
        row.setLayoutParams(lp);
        row.addView(statCard(0, "ACTIVE APPS", NEUTRAL));
        row.addView(statCard(1, "TLS", ENC));
        row.addView(statCard(2, "PLAINTEXT", PLAIN));
        row.addView(statCard(3, "UNVERIFIED", WARN));
        row.addView(statCard(4, "OPEN ALERTS", ACCENT));
        return row;
    }

    private View statCard(int slot, String label, int tone) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setBackground(statBg());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(dp(2), 0, dp(2), 0);
        card.setLayoutParams(lp);

        View rail = new View(this);
        GradientDrawable railBg = new GradientDrawable();
        railBg.setColor(tone);
        rail.setBackground(railBg);
        card.addView(rail, new LinearLayout.LayoutParams(dp(2),
                ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setPadding(dp(7), dp(8), dp(5), dp(8));
        column.setLayoutParams(new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView caption = text(label, 7.5f, MUTED, false);
        caption.setTypeface(Typeface.MONOSPACE);
        caption.setLetterSpacing(0.08f);
        caption.setMaxLines(1);

        TextView value = text("0", 17f, tone, true);
        value.setTypeface(Typeface.MONOSPACE);
        value.setPadding(0, dp(4), 0, 0);
        value.setMaxLines(1);

        TextView sub = text("", 7.5f, MUTED_2, false);
        sub.setTypeface(Typeface.MONOSPACE);
        sub.setPadding(0, dp(3), 0, 0);
        sub.setMaxLines(1);
        sub.setEllipsize(android.text.TextUtils.TruncateAt.END);

        column.addView(caption);
        column.addView(value);
        column.addView(sub);
        card.addView(column);

        statValues[slot] = value;
        statSubs[slot] = sub;
        return card;
    }

    private View panelHead() {
        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);
        head.setPadding(dp(13), dp(11), dp(13), dp(9));

        panelTitle = text("ALERTS", 11f, 0xFFB9C9DA, true);
        panelTitle.setLetterSpacing(0.16f);
        head.addView(panelTitle);

        panelCount = text("0", 9.5f, MUTED, false);
        panelCount.setTypeface(Typeface.MONOSPACE);
        panelCount.setPadding(dp(7), dp(1), dp(7), dp(1));
        panelCount.setBackground(chipBg(MUTED, 0.05f, 0.14f));
        LinearLayout.LayoutParams countLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        countLp.leftMargin = dp(8);
        panelCount.setLayoutParams(countLp);
        head.addView(panelCount);

        panelHint = text("newest first", 8.5f, MUTED_2, false);
        panelHint.setTypeface(Typeface.MONOSPACE);
        panelHint.setLetterSpacing(0.08f);
        panelHint.setGravity(Gravity.END);
        panelHint.setLayoutParams(new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        head.addView(panelHint);
        return head;
    }

    private View tabRow() {
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setBackground(chipBg(MUTED, 0.03f, 0.12f));
        bar.setPadding(dp(3), dp(3), dp(3), dp(3));
        LinearLayout.LayoutParams barLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        barLp.leftMargin = dp(11);
        barLp.rightMargin = dp(11);
        barLp.bottomMargin = dp(4);
        bar.setLayoutParams(barLp);

        String[] labels = {"Alerts", "Traffic", "Network"};
        for (int i = 0; i < labels.length; i++) {
            final int index = i;
            TextView tabView = text(labels[i], 10.5f, MUTED, false);
            tabView.setGravity(Gravity.CENTER);
            tabView.setPadding(0, dp(6), 0, dp(6));
            tabView.setLayoutParams(new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            tabView.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    tab = index;
                    styleTabs();
                    lastStamp = -1;
                    refresh();
                }
            });
            tabs[i] = tabView;
            bar.addView(tabView);
        }
        styleTabs();
        return bar;
    }

    private View footbar() {
        LinearLayout foot = new LinearLayout(this);
        foot.setOrientation(LinearLayout.VERTICAL);
        foot.setPadding(dp(4), dp(8), dp(4), 0);

        LinearLayout legend = new LinearLayout(this);
        legend.setOrientation(LinearLayout.HORIZONTAL);
        legend.setGravity(Gravity.CENTER_VERTICAL);
        legend.addView(legendItem("encrypted", ENC));
        legend.addView(legendItem("unencrypted", PLAIN));
        legend.addView(legendItem("unknown", UNK));
        legend.addView(legendItem("unverified", WARN));
        foot.addView(legend);

        footNote = text("", 9f, MUTED_2, false);
        footNote.setTypeface(Typeface.MONOSPACE);
        footNote.setPadding(0, dp(5), 0, 0);
        foot.addView(footNote);
        return foot;
    }

    private View legendItem(String label, int tone) {
        LinearLayout item = new LinearLayout(this);
        item.setOrientation(LinearLayout.HORIZONTAL);
        item.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams itemLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        itemLp.rightMargin = dp(11);
        item.setLayoutParams(itemLp);

        View dot = new View(this);
        GradientDrawable dotBg = new GradientDrawable();
        dotBg.setCornerRadius(dp(1.5f));
        dotBg.setColor(tone);
        dot.setBackground(dotBg);
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dp(6), dp(6));
        dotLp.rightMargin = dp(5);
        dot.setLayoutParams(dotLp);
        item.addView(dot);

        item.addView(text(label, 9f, MUTED_2, false));
        return item;
    }

    private void styleTabs() {
        for (int i = 0; i < tabs.length; i++) {
            if (tabs[i] == null) continue;
            boolean active = i == tab;
            tabs[i].setTextColor(active ? 0xFFE6EEFB : MUTED);
            tabs[i].setTypeface(Typeface.create(Typeface.DEFAULT, active ? Typeface.BOLD : Typeface.NORMAL));
            tabs[i].setBackground(active ? activeTabBg() : null);
        }
    }

    /* ---------------------------------------------------------------- refresh */

    private void refresh() {
        Monitor.Snapshot s = monitor.snapshot();

        int encrypted = 0;
        int unknown = 0;
        for (Monitor.Conn c : s.conns) {
            if ("encrypted".equals(c.encryption)) encrypted++;
            else if ("unknown".equals(c.encryption)) unknown++;
        }
        int newApps = 0;
        for (Traffic.AppUse a : s.apps) if (!a.known) newApps++;
        int critical = 0;
        for (Monitor.Alert a : s.alerts) if ("critical".equals(a.severity)) critical++;

        // Android denies /proc/net/tcp to apps (SELinux), so the socket counters are
        // unknowable rather than zero. Say so instead of reporting a false 0.
        boolean socketsBlocked = s.scanNote != null && !s.scanNote.isEmpty();
        String none = "—";

        statValues[0].setText(s.usageGranted ? String.valueOf(s.apps.size()) : none);
        statSubs[0].setText(s.usageGranted ? newApps + " new" : "needs access");
        statValues[0].setTextColor(s.usageGranted ? NEUTRAL : MUTED_2);

        statValues[1].setText(socketsBlocked ? none : String.valueOf(encrypted));
        statSubs[1].setText(socketsBlocked ? "blocked by OS" : s.total + " sockets");
        statValues[1].setTextColor(socketsBlocked ? MUTED_2 : ENC);

        if (s.dnsRunning) {
            statValues[2].setText(String.valueOf(s.plaintextDns));
            statSubs[2].setText("DNS lookups");
            statValues[2].setTextColor(PLAIN);
        } else {
            statValues[2].setText(socketsBlocked ? none : String.valueOf(s.plaintext));
            statSubs[2].setText(socketsBlocked ? "blocked by OS" : unknown + " unknown");
            statValues[2].setTextColor(socketsBlocked ? MUTED_2 : PLAIN);
        }
        statValues[3].setText(String.valueOf(s.unverified));
        statSubs[3].setText(s.trustedCount + " trusted");
        statValues[4].setText(String.valueOf(s.alerts.size()));
        statSubs[4].setText(critical + " critical");

        boolean running = WatchService.RUNNING;
        liveLabel.setText(running ? "LIVE" : "PAUSED");
        liveLabel.setTextColor(running ? ENC : WARN);
        liveBox.setBackground(pillBg(running ? ENC : WARN));
        if (watchBtn != null) watchBtn.setText(running ? "Stop" : "Start");

        String net = s.net == null ? "offline" : s.net.label();
        metaLine.setText(net + "  ·  baseline " + ago(s.baselineAt) + "  ·  "
                + s.appsKnown + " apps  ·  " + s.endpoints + " endpoints");

        if (tab == 0) {
            panelTitle.setText("ALERTS");
            panelHint.setText("newest first");
            panelCount.setText(String.valueOf(s.alerts.size()));
        } else if (tab == 1) {
            panelTitle.setText("TRAFFIC");
            panelHint.setText("last 2 min");
            panelCount.setText(String.valueOf(s.apps.size()));
        } else {
            panelTitle.setText("NETWORK");
            panelHint.setText("fingerprint");
            panelCount.setText(String.valueOf(s.networks));
        }

        if (!s.usageGranted && s.trafficNote != null && !s.trafficNote.isEmpty()) {
            footNote.setText(s.trafficNote);
            footNote.setTextColor(WARN);
        } else if (s.scanNote != null && !s.scanNote.isEmpty()) {
            footNote.setText(s.scanNote);
            footNote.setTextColor(PLAIN);
        } else {
            footNote.setText("scanning every 4.0s · tap an alert to trust or dismiss");
            footNote.setTextColor(MUTED_2);
        }

        long stamp = s.updatedAt * 31 + s.alerts.size() * 7 + tab;
        if (stamp != lastStamp) {
            lastStamp = stamp;
            rebuildRows();
        }
        panelFoot.setText("showing " + adapter.getCount() + " · " + s.listeners + " listening · "
                + s.appsKnown + " known apps · scan " + ago(s.updatedAt));
    }

    private void rebuildRows() {
        Monitor.Snapshot s = monitor.snapshot();
        int first = list.getFirstVisiblePosition();
        List<View> rows = new ArrayList<>();

        if (tab == 0) {
            for (Monitor.Alert a : s.alerts) rows.add(alertCard(a));
            if (rows.isEmpty()) {
                rows.add(emptyCard("No alerts",
                        "Nothing unverified or unencrypted is in play."));
            }
        } else if (tab == 1) {
            if (s.dnsRunning) {
                rows.add(captureControl());
            } else {
                rows.add(hintCard("Capture plaintext DNS",
                        "The socket table is closed to apps, but the system resolver can be captured: tap to allow a local DNS tunnel that records every lookup made in clear text.", 2));
            }
            if (!s.usageGranted) rows.add(hintCard("Per-app traffic is hidden",
                    "Android only reports other apps' traffic after you grant Usage access. Tap this row, then enable Anomaly Watch."));
            for (Traffic.AppUse a : s.apps) rows.add(appRow(a));
            if (s.apps.isEmpty() && s.usageGranted) {
                rows.add(emptyCard("No app traffic right now",
                        "Nothing moved data in the last two minutes."));
            }
            if (s.dnsRunning) {
                rows.add(sectionLabel("PLAINTEXT DNS · " + s.plaintextDns));
                for (Monitor.DnsEvent e : s.dns) rows.add(dnsRow(e));
                if (s.dns.isEmpty()) {
                    String privateDns = s.net == null ? null : s.net.privateDns;
                    boolean doh = privateDns != null && !privateDns.isEmpty()
                            && !"off".equals(privateDns);
                    if (doh) {
                        rows.add(hintCard("Private DNS is on",
                                "Name lookups leave encrypted (" + privateDns + "), so the tunnel sees none of them. Switch Private DNS to Off to record domains.", 3));
                    } else {
                        rows.add(emptyCard("No lookups yet",
                                "DNS capture is on. Domains will appear as apps resolve them."));
                    }
                }
            }
            if (!s.conns.isEmpty()) {
                rows.add(sectionLabel("RAW SOCKETS · " + s.conns.size()));
                for (Monitor.Conn c : s.conns) rows.add(socketRow(c));
            }
        } else {
            if (s.net != null) {
                rows.add(sectionLabel("CURRENT NETWORK"));
                for (String line : s.net.lines()) {
                    String[] parts = line.split("\\|", 2);
                    rows.add(kvRow(parts[0], parts.length > 1 ? parts[1] : ""));
                }
            } else {
                rows.add(emptyCard("Offline", "No active network to describe."));
            }
            rows.add(sectionLabel("BASELINE"));
            rows.add(kvRow("endpoints", String.valueOf(s.endpoints)));
            rows.add(kvRow("apps", s.appsKnown + " known"));
            rows.add(kvRow("networks", String.valueOf(s.networks)));
            rows.add(kvRow("trusted endpoints", String.valueOf(s.trustedCount)));
            rows.add(kvRow("last scan", ago(s.updatedAt)));
        }

        adapter.set(rows);
        list.setSelectionFromTop(first, 0);
    }

    /* ------------------------------------------------------------------ cards */

    private View alertCard(final Monitor.Alert a) {
        int tone = severityTone(a.severity);
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setBackground(alertBg(tone, "critical".equals(a.severity)));
        card.setPadding(0, 0, 0, 0);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(8);
        card.setLayoutParams(lp);

        View rail = new View(this);
        GradientDrawable railBg = new GradientDrawable();
        railBg.setColor(tone);
        rail.setBackground(railBg);
        card.addView(rail, new LinearLayout.LayoutParams(dp(2),
                ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(11), dp(9), dp(11), dp(9));
        body.setLayoutParams(new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.HORIZONTAL);
        top.setGravity(Gravity.CENTER_VERTICAL);
        TextView sev = text(a.severity.toUpperCase(Locale.US), 8.5f, tone, true);
        sev.setTypeface(Typeface.MONOSPACE);
        sev.setLetterSpacing(0.14f);
        sev.setPadding(dp(6), dp(1), dp(6), dp(1));
        sev.setBackground(chipBg(tone, 0.09f, 0.32f));
        top.addView(sev);
        TextView time = text(clock.format(new Date(a.at)), 9f, MUTED_2, false);
        time.setTypeface(Typeface.MONOSPACE);
        time.setGravity(Gravity.END);
        time.setLayoutParams(new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        top.addView(time);
        body.addView(top);

        TextView title = text(a.title, 12f, TITLE, true);
        title.setPadding(0, dp(6), 0, dp(3));
        body.addView(title);

        TextView detail = text(a.detail, 10.5f, MUTED, false);
        detail.setLineSpacing(dp(2), 1f);
        body.addView(detail);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setPadding(0, dp(8), 0, 0);
        if (a.ip != null && !a.ip.isEmpty() && !"system".equals(a.type)) {
            final String ip = a.ip;
            actions.addView(miniButton("Trust " + (ip.length() > 20 ? "endpoint" : ip), true,
                    new View.OnClickListener() {
                        @Override
                        public void onClick(View v) {
                            monitor.trust(ip);
                            refresh();
                        }
                    }));
        }
        if (!"system".equals(a.type)) {
            actions.addView(miniButton("Dismiss", false, new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    monitor.dismiss(a.id);
                    refresh();
                }
            }));
        }
        if (actions.getChildCount() > 0) body.addView(actions);

        card.addView(body);
        card.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showAlert(a);
            }
        });
        return card;
    }

    private View appRow(final Traffic.AppUse a) {
        int tone = a.known ? ACCENT : WARN;
        LinearLayout card = rowShell(tone);

        LinearLayout left = new LinearLayout(this);
        left.setOrientation(LinearLayout.VERTICAL);
        left.setLayoutParams(new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView label = text(a.label, 11.5f, 0xFFDBE7F5, false);
        label.setTypeface(Typeface.MONOSPACE);
        label.setMaxLines(1);
        label.setEllipsize(android.text.TextUtils.TruncateAt.END);
        left.addView(label);

        String pkg = a.pkg.isEmpty() ? "" : a.pkg + "  ·  ";
        TextView sub = text(pkg + "uid " + a.uid, 9f, MUTED_2, false);
        sub.setTypeface(Typeface.MONOSPACE);
        sub.setPadding(0, dp(3), 0, 0);
        sub.setMaxLines(1);
        sub.setEllipsize(android.text.TextUtils.TruncateAt.END);
        left.addView(sub);
        card.addView(left);

        LinearLayout right = new LinearLayout(this);
        right.setOrientation(LinearLayout.VERTICAL);
        right.setGravity(Gravity.END);

        TextView vol = text("↓ " + Monitor.bytes(a.rx), 10f, 0xFFA9BED4, false);
        vol.setTypeface(Typeface.MONOSPACE);
        vol.setGravity(Gravity.END);
        TextView up = text("↑ " + Monitor.bytes(a.tx), 10f, 0xFFA9BED4, false);
        up.setTypeface(Typeface.MONOSPACE);
        up.setGravity(Gravity.END);
        up.setPadding(0, dp(3), 0, 0);
        right.addView(vol);
        right.addView(up);
        if (!a.known) {
            TextView badge = text("NEW", 8f, WARN, true);
            badge.setTypeface(Typeface.MONOSPACE);
            badge.setLetterSpacing(0.12f);
            badge.setPadding(dp(5), dp(1), dp(5), dp(1));
            badge.setBackground(chipBg(WARN, 0.08f, 0.24f));
            LinearLayout.LayoutParams badgeLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            badgeLp.topMargin = dp(5);
            badge.setLayoutParams(badgeLp);
            badge.setGravity(Gravity.CENTER);
            right.addView(badge);
        }
        card.addView(right);
        return card;
    }

    private View socketRow(Monitor.Conn c) {
        int tone = riskTone(c.risk);
        LinearLayout card = rowShell(tone);

        LinearLayout left = new LinearLayout(this);
        left.setOrientation(LinearLayout.VERTICAL);
        left.setLayoutParams(new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        String endpoint = c.listener
                ? c.localIp + ":" + c.localPort
                : c.remoteIp + ":" + c.remotePort;
        String arrow = c.listener ? "◂" : c.inbound ? "←" : "→";

        TextView proc = text(c.process, 11.5f, 0xFFDBE7F5, false);
        proc.setTypeface(Typeface.MONOSPACE);
        proc.setMaxLines(1);
        proc.setEllipsize(android.text.TextUtils.TruncateAt.END);
        left.addView(proc);

        TextView ep = text(arrow + " " + endpoint, 10f, 0xFFA9BED4, false);
        ep.setTypeface(Typeface.MONOSPACE);
        ep.setPadding(0, dp(3), 0, 0);
        ep.setMaxLines(1);
        ep.setEllipsize(android.text.TextUtils.TruncateAt.END);
        left.addView(ep);

        LinearLayout badges = new LinearLayout(this);
        badges.setOrientation(LinearLayout.HORIZONTAL);
        badges.setPadding(0, dp(5), 0, 0);
        int encTone = "plaintext".equals(c.encryption) ? PLAIN
                : "encrypted".equals(c.encryption) ? ENC : UNK;
        String encText = "plaintext".equals(c.encryption) ? "NO TLS"
                : "encrypted".equals(c.encryption) ? "TLS" : "UNKNOWN";
        badges.addView(badge(encText, encTone));
        badges.addView(badge(c.service, UNK));
        left.addView(badges);
        card.addView(left);

        TextView risk = text(riskLabel(c.risk).toUpperCase(Locale.US), 8.5f, tone, true);
        risk.setTypeface(Typeface.MONOSPACE);
        risk.setLetterSpacing(0.1f);
        risk.setPadding(dp(6), dp(2), dp(6), dp(2));
        risk.setBackground(chipBg(tone, 0.09f, 0.28f));
        risk.setGravity(Gravity.CENTER);
        card.addView(risk);
        return card;
    }

    private View dnsRow(Monitor.DnsEvent event) {
        LinearLayout card = rowShell(PLAIN);

        LinearLayout left = new LinearLayout(this);
        left.setOrientation(LinearLayout.VERTICAL);
        left.setLayoutParams(new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView domain = text(event.domain, 11.5f, 0xFFDBE7F5, false);
        domain.setTypeface(Typeface.MONOSPACE);
        domain.setMaxLines(1);
        domain.setEllipsize(android.text.TextUtils.TruncateAt.END);
        left.addView(domain);

        TextView sub = text(event.app + "  ·  " + event.resolver, 9f, MUTED_2, false);
        sub.setTypeface(Typeface.MONOSPACE);
        sub.setPadding(0, dp(3), 0, 0);
        sub.setMaxLines(1);
        sub.setEllipsize(android.text.TextUtils.TruncateAt.END);
        left.addView(sub);
        card.addView(left);

        TextView time = text(clock.format(new Date(event.at)), 8.5f, MUTED_2, false);
        time.setTypeface(Typeface.MONOSPACE);
        card.addView(time);
        return card;
    }

    private View kvRow(String key, String value) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(10), dp(8), dp(10), dp(8));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(5);
        row.setLayoutParams(lp);
        row.setBackground(rowBg(LINE_SOFT));

        TextView k = text(key.toUpperCase(Locale.US), 8.5f, MUTED_2, false);
        k.setTypeface(Typeface.MONOSPACE);
        k.setLetterSpacing(0.1f);
        k.setSingleLine(true);
        row.addView(k);

        TextView v = text(value, 10.5f, TEXT, false);
        v.setTypeface(Typeface.MONOSPACE);
        v.setGravity(Gravity.END);
        v.setLayoutParams(new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        v.setMaxLines(2);
        v.setEllipsize(android.text.TextUtils.TruncateAt.END);
        row.addView(v);
        return row;
    }

    private View sectionLabel(String label) {
        TextView view = text(label, 8.5f, MUTED_2, true);
        view.setTypeface(Typeface.MONOSPACE);
        view.setLetterSpacing(0.14f);
        view.setPadding(dp(10), dp(8), dp(10), dp(6));
        return view;
    }

    private View hintCard(String title, String detail) {
        return hintCard(title, detail, 1);
    }

    /** action 1 = usage access settings, action 2 = start the DNS capture. */
    private View hintCard(String title, String detail, final int action) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(alertBg(WARN, false));
        card.setPadding(dp(12), dp(10), dp(12), dp(10));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(8);
        card.setLayoutParams(lp);

        TextView head = text(title, 11.5f, WARN, true);
        card.addView(head);
        TextView body = text(detail, 10.5f, MUTED, false);
        body.setPadding(0, dp(4), 0, 0);
        card.addView(body);
        card.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (action == 2) startDnsCapture();
                else if (action == 3) openPrivateDns();
                else openUsageSettings();
            }
        });
        return card;
    }

    /** Status line for a running capture, with the way out of it. */
    private View captureControl() {
        LinearLayout row = rowShell(ENC);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.addView(text("DNS capture is on", 10.5f, ENC, true));
        box.addView(text("Only port 53 enters the tunnel; every other flow keeps its path.",
                9f, MUTED, false));
        row.addView(box, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(miniButton("Stop", false, new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                stopDnsCapture();
                refresh();
            }
        }));
        return row;
    }

    private View emptyCard(String title, String detail) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(rowBg(LINE_SOFT));
        card.setPadding(dp(14), dp(18), dp(14), dp(18));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(8);
        card.setLayoutParams(lp);

        TextView head = text(title, 11f, MUTED, false);
        head.setTypeface(Typeface.MONOSPACE);
        head.setGravity(Gravity.CENTER);
        card.addView(head);
        TextView body = text(detail, 9.5f, MUTED_2, false);
        body.setTypeface(Typeface.MONOSPACE);
        body.setGravity(Gravity.CENTER);
        body.setPadding(0, dp(5), 0, 0);
        card.addView(body);
        return card;
    }

    /* ---------------------------------------------------------------- widgets */

    private LinearLayout rowShell(int tone) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setGravity(Gravity.CENTER_VERTICAL);
        card.setBackground(rowBg(LINE));
        card.setPadding(dp(10), dp(8), dp(10), dp(8));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(5);
        card.setLayoutParams(lp);
        card.setMinimumHeight(dp(46));
        return card;
    }

    private TextView badge(String label, int tone) {
        TextView view = text(label.toUpperCase(Locale.US), 8f, tone, true);
        view.setTypeface(Typeface.MONOSPACE);
        view.setLetterSpacing(0.1f);
        view.setPadding(dp(5), dp(1), dp(5), dp(1));
        view.setBackground(chipBg(tone, 0.08f, 0.22f));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = dp(5);
        view.setLayoutParams(lp);
        return view;
    }

    private TextView miniButton(String label, boolean primary, View.OnClickListener listener) {
        int tone = primary ? ENC : MUTED;
        TextView view = text(label, 10f, tone, false);
        view.setPadding(dp(9), dp(5), dp(9), dp(5));
        view.setBackground(chipBg(tone, primary ? 0.06f : 0f, 0.26f));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = dp(6);
        view.setLayoutParams(lp);
        view.setOnClickListener(listener);
        return view;
    }

    private TextView chromeButton(String label, boolean ghost, View.OnClickListener listener) {
        TextView view = text(label, 10.5f, ghost ? MUTED : TEXT, false);
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(8));
        bg.setColor(ghost ? Color.TRANSPARENT : 0xFF142031);
        bg.setStroke(1, ghost ? LINE : 0xFF22334A);
        view.setBackground(bg);
        view.setGravity(Gravity.CENTER);
        view.setPadding(dp(10), dp(6), dp(10), dp(6));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(dp(2), 0, dp(2), 0);
        view.setLayoutParams(lp);
        view.setOnClickListener(listener);
        return view;
    }

    private TextView text(String value, float size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        return view;
    }

    /* ------------------------------------------------------------------ drawables */

    private GradientDrawable panelBg(float radius) {
        GradientDrawable bg = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{PANEL_TOP, PANEL_BOT});
        bg.setCornerRadius(dp(radius));
        bg.setStroke(1, LINE);
        return bg;
    }

    private GradientDrawable topbarBg() {
        GradientDrawable bg = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{0xFF141E2B, 0xFF0B1119});
        bg.setCornerRadius(dp(14));
        bg.setStroke(1, LINE);
        return bg;
    }

    private GradientDrawable statBg() {
        GradientDrawable bg = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{0xFF101823, 0xFF090E15});
        bg.setCornerRadius(dp(12));
        bg.setStroke(1, LINE);
        return bg;
    }

    private GradientDrawable rowBg(int stroke) {
        GradientDrawable bg = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{0xFF0D141D, 0xFF0A1017});
        bg.setCornerRadius(dp(9));
        bg.setStroke(1, stroke);
        return bg;
    }

    private GradientDrawable alertBg(int tone, boolean tinted) {
        int top = tinted ? blend(tone, 0x17) : 0xFF121A25;
        GradientDrawable bg = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{top, 0xFF0B1119});
        bg.setCornerRadius(dp(9));
        bg.setStroke(1, LINE);
        return bg;
    }

    private GradientDrawable activeTabBg() {
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(6));
        bg.setColor(0xFF1A2A3E);
        bg.setStroke(1, 0xFF26384F);
        return bg;
    }

    private GradientDrawable chipBg(int tone, float fillAlpha, float strokeAlpha) {
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(5));
        bg.setColor(Color.argb((int) (fillAlpha * 255), Color.red(tone), Color.green(tone), Color.blue(tone)));
        bg.setStroke(1, Color.argb((int) (strokeAlpha * 255), Color.red(tone), Color.green(tone), Color.blue(tone)));
        return bg;
    }

    private GradientDrawable pillBg(int tone) {
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(999));
        bg.setColor(Color.argb((int) (0.08f * 255), Color.red(tone), Color.green(tone), Color.blue(tone)));
        bg.setStroke(1, Color.argb((int) (0.3f * 255), Color.red(tone), Color.green(tone), Color.blue(tone)));
        return bg;
    }

    private GradientDrawable topStroke() {
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.TRANSPARENT);
        return bg;
    }

    private static int blend(int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }

    /* ------------------------------------------------------------------- rows */

    private final class RowsAdapter extends BaseAdapter {
        final List<View> rows = new ArrayList<>();

        void set(List<View> next) {
            rows.clear();
            rows.addAll(next);
            notifyDataSetChanged();
        }

        @Override
        public int getCount() {
            return rows.size();
        }

        @Override
        public Object getItem(int position) {
            return rows.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            return rows.get(position);
        }

        @Override
        public boolean isEnabled(int position) {
            return false;
        }
    }

    /* ---------------------------------------------------------------- actions */

    private void showAlert(final Monitor.Alert a) {
        AlertDialog.Builder b = new AlertDialog.Builder(this);
        b.setTitle(a.title);
        b.setMessage(a.detail + "\n\n" + a.severity.toUpperCase(Locale.US) + " · " + a.type);
        b.setNegativeButton("Close", null);
        b.setPositiveButton("Dismiss", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                monitor.dismiss(a.id);
                refresh();
            }
        });
        if (a.ip != null && !a.ip.isEmpty()) {
            b.setNeutralButton("Trust " + a.ip, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    monitor.trust(a.ip);
                    refresh();
                }
            });
        }
        b.show();
    }

    private void startDnsCapture() {
        try {
            Intent prepare = VpnService.prepare(this);
            if (prepare != null) {
                startActivityForResult(prepare, REQ_VPN);
            } else {
                getSharedPreferences("aw", MODE_PRIVATE).edit()
                        .putBoolean("dns_stopped", false).apply();
                launchCapture();
            }
        } catch (Exception ignored) {
            // VPN unavailable on this device
        }
    }

    /** The capture is a foreground service, so Android keeps it after the app is closed. */
    private void launchCapture() {
        try {
            startForegroundService(new Intent(this, DnsVpnService.class));
        } catch (Exception e) {
            try {
                startService(new Intent(this, DnsVpnService.class));
            } catch (Exception ignored) {
                // start refused
            }
        }
    }

    private void stopDnsCapture() {
        getSharedPreferences("aw", MODE_PRIVATE).edit()
                .putBoolean("dns_stopped", true).apply();
        // stopService() cannot bring down a foreground service, so ask the service
        // itself to tear the tunnel down.
        if (DnsVpnService.RUNNING) {
            try {
                startService(new Intent(this, DnsVpnService.class)
                        .setAction(DnsVpnService.ACTION_STOP));
            } catch (Exception ignored) {
                // the service is gone already
            }
        }
        handler.postDelayed(refreshLoop, 400);
    }

    private void openPrivateDns() {
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                startActivity(new Intent("android.settings.PRIVATE_DNS_SETTINGS"));
            } else {
                startActivity(new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS));
            }
        } catch (Exception ignored) {
            // no settings activity available
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            getSharedPreferences("aw", MODE_PRIVATE).edit()
                    .putBoolean("dns_stopped", false).apply();
            launchCapture();
            handler.postDelayed(refreshLoop, 600);
        }
    }

    private void openUsageSettings() {
        try {
            startActivity(new Intent(android.provider.Settings.ACTION_USAGE_ACCESS_SETTINGS));
        } catch (Exception e) {
            try {
                startActivity(new Intent(android.provider.Settings.ACTION_SETTINGS));
            } catch (Exception ignored) {
                // no settings activity available
            }
        }
    }

    private void startWatch() {
        try {
            startForegroundService(new Intent(this, WatchService.class));
        } catch (Exception ignored) {
            // foreground start refused; the dashboard still updates while open
        }
    }

    private void askForNotifications() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 1);
        }
    }

    /* ------------------------------------------------------------------ format */

    private int severityTone(String severity) {
        if ("critical".equals(severity)) return CRIT;
        if ("high".equals(severity)) return PLAIN;
        if ("medium".equals(severity)) return WARN;
        if ("low".equals(severity)) return 0xFF7D90A6;
        return ACCENT;
    }

    private int riskTone(int risk) {
        if (risk >= 70) return CRIT;
        if (risk >= 50) return PLAIN;
        if (risk >= 28) return WARN;
        if (risk > 8) return ACCENT;
        return MUTED_2;
    }

    private String riskLabel(int risk) {
        if (risk >= 70) return "critical";
        if (risk >= 50) return "high";
        if (risk >= 28) return "medium";
        if (risk > 8) return "low";
        return "clean";
    }

    private String ago(long ts) {
        if (ts <= 0) return "never";
        long sec = Math.max(0, (System.currentTimeMillis() - ts) / 1000);
        if (sec < 10) return "just now";
        if (sec < 60) return sec + "s ago";
        long min = sec / 60;
        if (min < 60) return min + "m ago";
        long hr = min / 60;
        if (hr < 24) return hr + "h ago";
        return (hr / 24) + "d ago";
    }

    private int dp(float value) {
        return (int) (getResources().getDisplayMetrics().density * value + 0.5f);
    }
}
