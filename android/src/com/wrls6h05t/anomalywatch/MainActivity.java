package com.wrls6h05t.anomalywatch;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
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
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {

    private static final int BG = 0xFF0B0F14;
    private static final int CARD = 0xFF10161F;
    private static final int STROKE = 0xFF1F2937;
    private static final int TEXT = 0xFFE6EDF3;
    private static final int MUTED = 0xFF8B949E;
    private static final int DIM = 0xFF5B6672;
    private static final int ACCENT = 0xFF58A6FF;
    private static final int RED = 0xFFF87171;
    private static final int HOT = 0xFFFB7185;
    private static final int AMBER = 0xFFFBBF24;
    private static final int GREEN = 0xFF4ADE80;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat clock = new SimpleDateFormat("HH:mm:ss", Locale.US);

    private Monitor monitor;
    private ListView list;
    private RowsAdapter adapter;
    private TextView status;
    private TextView subtitle;
    private TextView note;
    private final TextView[] statValues = new TextView[4];
    private final Button[] tabs = new Button[3];
    private Button watchBtn;
    private int tab;

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

    /* -------------------------------------------------------------------- ui */

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setPadding(dp(14), dp(14), dp(14), dp(10));

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);

        TextView title = new TextView(this);
        title.setText("Anomaly Watch");
        title.setTextSize(19f);
        title.setTextColor(TEXT);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(title);

        status = new TextView(this);
        status.setTextSize(10.5f);
        status.setTextColor(ACCENT);
        header.addView(status);
        root.addView(header);

        subtitle = new TextView(this);
        subtitle.setTextSize(10.5f);
        subtitle.setTextColor(MUTED);
        subtitle.setPadding(0, dp(4), 0, dp(10));
        root.addView(subtitle);

        LinearLayout stats = new LinearLayout(this);
        stats.setOrientation(LinearLayout.HORIZONTAL);
        stats.addView(statCard("Connections", TEXT, 0));
        stats.addView(statCard("Unverified", AMBER, 1));
        stats.addView(statCard("Unencrypted", HOT, 2));
        stats.addView(statCard("Alerts", RED, 3));
        root.addView(stats);

        LinearLayout tabRow = new LinearLayout(this);
        tabRow.setOrientation(LinearLayout.HORIZONTAL);
        tabRow.setPadding(0, dp(10), 0, dp(6));
        String[] names = {"Alerts", "Sockets", "Network"};
        for (int i = 0; i < names.length; i++) {
            final int index = i;
            Button b = new Button(this);
            b.setText(names[i]);
            b.setAllCaps(false);
            b.setTextSize(12f);
            b.setPadding(0, 0, 0, 0);
            b.setMinHeight(0);
            b.setMinimumHeight(dp(34));
            b.setBackgroundTintList(ColorStateList.valueOf(CARD));
            b.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            b.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    tab = index;
                    styleTabs();
                    rebuildRows(true);
                }
            });
            tabs[i] = b;
            tabRow.addView(b);
        }
        root.addView(tabRow);
        styleTabs();

        list = new ListView(this);
        list.setBackgroundColor(BG);
        list.setDivider(null);
        list.setSelector(android.R.color.transparent);
        list.setVerticalScrollBarEnabled(false);
        list.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        adapter = new RowsAdapter();
        list.setAdapter(adapter);
        list.setOnItemClickListener(new android.widget.AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(android.widget.AdapterView<?> parent, View view, int position, long id) {
                Row row = adapter.rows.get(position);
                if (row != null && row.alert != null) showAlert(row.alert);
            }
        });
        root.addView(list);

        note = new TextView(this);
        note.setTextSize(9.5f);
        note.setTextColor(DIM);
        note.setPadding(0, dp(6), 0, dp(6));
        root.addView(note);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.addView(actionButton("Re-baseline", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                monitor.baselineNow();
                refresh();
            }
        }));
        actions.addView(actionButton("Clear alerts", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                monitor.clearFeed();
                refresh();
            }
        }));
        watchBtn = actionButton("Stop", new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (WatchService.RUNNING) stopService(new Intent(MainActivity.this, WatchService.class));
                else startWatch();
                handler.postDelayed(refreshLoop, 400);
                refresh();
            }
        });
        actions.addView(watchBtn);
        root.addView(actions);

        setContentView(root);
    }

    private LinearLayout statCard(String label, int accent, int slot) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(CARD);
        bg.setCornerRadius(dp(10));
        bg.setStroke(1, STROKE);
        box.setBackground(bg);
        box.setPadding(dp(10), dp(7), dp(10), dp(7));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(dp(3), 0, dp(3), 0);
        box.setLayoutParams(lp);

        TextView value = new TextView(this);
        value.setText("0");
        value.setTextSize(19f);
        value.setTextColor(accent);
        value.setTypeface(Typeface.DEFAULT_BOLD);
        TextView caption = new TextView(this);
        caption.setText(label);
        caption.setTextSize(9f);
        caption.setTextColor(MUTED);

        box.addView(value);
        box.addView(caption);
        statValues[slot] = value;
        return box;
    }

    private Button actionButton(String text, View.OnClickListener listener) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextSize(11.5f);
        b.setTextColor(TEXT);
        b.setBackgroundTintList(ColorStateList.valueOf(CARD));
        b.setMinHeight(0);
        b.setMinimumHeight(dp(38));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(dp(3), 0, dp(3), 0);
        b.setLayoutParams(lp);
        b.setOnClickListener(listener);
        return b;
    }

    private void styleTabs() {
        for (int i = 0; i < tabs.length; i++) {
            if (tabs[i] == null) continue;
            boolean active = i == tab;
            tabs[i].setTextColor(active ? ACCENT : MUTED);
            tabs[i].setTypeface(active ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
            tabs[i].setBackgroundTintList(ColorStateList.valueOf(active ? 0xFF16202B : CARD));
        }
    }

    /* ---------------------------------------------------------------- refresh */

    private void refresh() {
        Monitor.Snapshot s = monitor.snapshot();
        statValues[0].setText(String.valueOf(s.total));
        statValues[1].setText(String.valueOf(s.unverified));
        statValues[2].setText(String.valueOf(s.plaintext));
        statValues[3].setText(String.valueOf(s.alerts.size()));

        status.setText(WatchService.RUNNING ? "● watching" : "○ stopped");
        status.setTextColor(WatchService.RUNNING ? GREEN : MUTED);

        String netLabel = s.net == null ? "offline" : s.net.label();
        subtitle.setText(netLabel + " · baseline " + ago(s.baselineAt) + " · "
                + s.endpoints + " endpoints · " + s.listeners + " listening");

        if (s.scanNote != null && !s.scanNote.isEmpty()) {
            note.setText(s.scanNote);
            note.setTextColor(AMBER);
        } else {
            note.setText("Tap an alert to trust the endpoint or dismiss it. Android may hide sockets owned by other apps.");
            note.setTextColor(DIM);
        }

        if (watchBtn != null) watchBtn.setText(WatchService.RUNNING ? "Stop" : "Start");

        long stamp = s.updatedAt * 31 + s.alerts.size() * 7 + tab;
        if (stamp != lastStamp) {
            lastStamp = stamp;
            rebuildRows(false);
        }
    }

    private long lastStamp = -1;

    private void rebuildRows(boolean force) {
        Monitor.Snapshot s = monitor.snapshot();
        int first = list.getFirstVisiblePosition();
        List<Row> rows = new ArrayList<>();

        if (tab == 0) {
            for (Monitor.Alert a : s.alerts) {
                rows.add(new Row(a.title, a.detail,
                        a.severity.toUpperCase(Locale.US) + " · " + clock.format(new Date(a.at))
                                + (a.ip == null || a.ip.isEmpty() ? "" : " · " + a.ip),
                        severityColor(a.severity), a));
            }
            if (rows.isEmpty()) {
                rows.add(new Row("No open alerts", "Nothing unverified or unencrypted has shown up yet.",
                        "baseline " + ago(s.baselineAt), GREEN, null));
            }
        } else if (tab == 1) {
            for (Monitor.Conn c : s.conns) {
                String endpoint = c.listener
                        ? c.localIp + ":" + c.localPort
                        : c.remoteIp + ":" + c.remotePort;
                String arrow = c.listener ? "◂" : c.inbound ? "←" : "→";
                String enc;
                if ("plaintext".equals(c.encryption)) enc = "NO TLS";
                else if ("encrypted".equals(c.encryption)) enc = "TLS";
                else enc = "unknown";
                String dir = c.listener
                        ? (c.exposed ? "listening · all interfaces" : "listening")
                        : c.inbound ? "inbound" : "outbound";
                rows.add(new Row(c.process + "  " + arrow + "  " + endpoint,
                        c.service + " · " + enc + " · risk " + c.risk,
                        c.proto.toUpperCase(Locale.US) + " " + c.state + " · uid " + c.uid + " · " + dir
                                + (c.verified ? "" : " · unverified"),
                        riskColor(c.risk), null));
            }
            if (rows.isEmpty()) {
                rows.add(new Row("No sockets visible",
                        "The platform returned an empty socket table for this app.",
                        "scan " + ago(s.updatedAt), AMBER, null));
            }
        } else {
            if (s.net != null) {
                rows.add(new Row("Network", s.net.describe(), s.net.metered ? "metered" : "unmetered",
                        ACCENT, null));
                for (String line : s.net.lines()) {
                    String[] parts = line.split("\\|", 2);
                    rows.add(new Row(parts[0], parts.length > 1 ? parts[1] : "", "", TEXT, null));
                }
            } else {
                rows.add(new Row("Offline", "No active network to describe.", "", MUTED, null));
            }
            rows.add(new Row("Baseline",
                    s.endpoints + " endpoints · " + s.processes + " processes · " + s.networks + " networks",
                    "trusted " + s.trustedCount + " · updated " + ago(s.updatedAt), TEXT, null));
        }

        adapter.set(rows);
        if (!force) list.setSelectionFromTop(first, 0);
    }

    private int severityColor(String severity) {
        if ("critical".equals(severity)) return RED;
        if ("high".equals(severity)) return HOT;
        if ("medium".equals(severity)) return AMBER;
        if ("low".equals(severity)) return ACCENT;
        return MUTED;
    }

    private int riskColor(int risk) {
        if (risk >= 70) return RED;
        if (risk >= 50) return HOT;
        if (risk >= 28) return AMBER;
        if (risk > 8) return ACCENT;
        return TEXT;
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

    /* ---------------------------------------------------------------- actions */

    private void showAlert(final Monitor.Alert a) {
        AlertDialog.Builder b = new AlertDialog.Builder(this);
        b.setTitle(a.title);
        b.setMessage(a.detail + "\n\n" + a.severity.toUpperCase(Locale.US) + " · " + a.type);
        b.setNegativeButton("Close", null);
        b.setPositiveButton("Dismiss", new android.content.DialogInterface.OnClickListener() {
            @Override
            public void onClick(android.content.DialogInterface dialog, int which) {
                monitor.dismiss(a.id);
                refresh();
            }
        });
        if (a.ip != null && !a.ip.isEmpty()) {
            b.setNeutralButton("Trust " + a.ip, new android.content.DialogInterface.OnClickListener() {
                @Override
                public void onClick(android.content.DialogInterface dialog, int which) {
                    monitor.trust(a.ip);
                    refresh();
                }
            });
        }
        b.show();
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

    private int dp(float value) {
        return (int) (getResources().getDisplayMetrics().density * value + 0.5f);
    }

    /* ------------------------------------------------------------------ rows */

    private static final class Row {
        final String title;
        final String detail;
        final String meta;
        final int color;
        final Monitor.Alert alert;

        Row(String title, String detail, String meta, int color, Monitor.Alert alert) {
            this.title = title;
            this.detail = detail == null ? "" : detail;
            this.meta = meta == null ? "" : meta;
            this.color = color;
            this.alert = alert;
        }
    }

    private final class RowsAdapter extends BaseAdapter {
        final List<Row> rows = new ArrayList<>();

        void set(List<Row> next) {
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
            Row r = rows.get(position);
            LinearLayout box = new LinearLayout(MainActivity.this);
            box.setOrientation(LinearLayout.VERTICAL);
            box.setPadding(dp(12), dp(10), dp(12), dp(10));

            GradientDrawable bg = new GradientDrawable();
            bg.setColor(CARD);
            bg.setCornerRadius(dp(9));
            bg.setStroke(1, STROKE);
            box.setBackground(bg);

            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.setMargins(0, 0, 0, dp(6));
            box.setLayoutParams(lp);

            TextView title = new TextView(MainActivity.this);
            title.setText(r.title);
            title.setTextSize(13f);
            title.setTextColor(r.color);
            title.setTypeface(Typeface.DEFAULT_BOLD);

            TextView detail = new TextView(MainActivity.this);
            detail.setText(r.detail);
            detail.setTextSize(11f);
            detail.setTextColor(MUTED);
            detail.setPadding(0, dp(3), 0, 0);

            TextView meta = new TextView(MainActivity.this);
            meta.setText(r.meta);
            meta.setTextSize(9.5f);
            meta.setTextColor(DIM);
            meta.setPadding(0, dp(4), 0, 0);

            box.addView(title);
            box.addView(detail);
            box.addView(meta);
            return box;
        }
    }
}
