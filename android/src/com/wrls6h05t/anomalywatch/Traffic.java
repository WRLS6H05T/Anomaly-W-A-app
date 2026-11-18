package com.wrls6h05t.anomalywatch;

import android.app.AppOpsManager;
import android.app.usage.NetworkStats;
import android.app.usage.NetworkStatsManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.Process;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Per-app network usage.
 *
 * The kernel socket table is unreadable for ordinary apps on modern Android, so
 * the socket-level view is usually empty. NetworkStatsManager reports what each
 * UID actually transferred, which needs the Usage access app-op (granted in
 * Settings) but no root.
 */
final class Traffic {

    static final class AppUse {
        String key = "";
        String label = "";
        String pkg = "";
        int uid;
        long rx;
        long tx;
        boolean known;

        long total() {
            return rx + tx;
        }
    }

    static final class Result {
        final List<AppUse> apps = new ArrayList<>();
        boolean granted;
        String note = "";
    }

    private static final Map<Integer, String> LABELS = new HashMap<>();
    private static final Map<Integer, String> PKGS = new HashMap<>();

    private Traffic() {
    }

    static boolean hasAccess(Context ctx) {
        try {
            AppOpsManager ops = (AppOpsManager) ctx.getSystemService(Context.APP_OPS_SERVICE);
            if (ops == null) return false;
            int mode = ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(), ctx.getPackageName());
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) {
            return false;
        }
    }

    static Result sample(Context ctx, long windowMs) {
        Result result = new Result();
        if (!hasAccess(ctx)) {
            result.note = "Usage access is off, so per-app traffic is hidden. Tap the first row to grant it.";
            return result;
        }
        result.granted = true;

        NetworkStatsManager manager =
                (NetworkStatsManager) ctx.getSystemService(Context.NETWORK_STATS_SERVICE);
        if (manager == null) {
            result.note = "This device has no traffic statistics service.";
            return result;
        }

        long now = System.currentTimeMillis();
        long from = now - windowMs;
        Map<Integer, AppUse> byUid = new HashMap<>();
        int[] types = {
                ConnectivityManager.TYPE_WIFI,
                ConnectivityManager.TYPE_MOBILE,
                ConnectivityManager.TYPE_ETHERNET
        };

        for (int type : types) {
            NetworkStats stats = null;
            try {
                stats = manager.querySummary(type, null, from, now);
                while (stats != null && stats.hasNextBucket()) {
                    NetworkStats.Bucket bucket = new NetworkStats.Bucket();
                    stats.getNextBucket(bucket);
                    long rx = bucket.getRxBytes();
                    long tx = bucket.getTxBytes();
                    if (rx <= 0 && tx <= 0) continue;
                    int uid = bucket.getUid();
                    if (uid < 0) continue;
                    AppUse use = byUid.get(uid);
                    if (use == null) {
                        use = new AppUse();
                        use.uid = uid;
                        byUid.put(uid, use);
                    }
                    use.rx += rx;
                    use.tx += tx;
                }
            } catch (SecurityException e) {
                // Some devices refuse one transport (mobile without a subscriber id).
                // hasAccess() is re-checked every tick, so keep the transports that worked.
            } catch (Exception ignored) {
                // transport without stats, or a build that refuses this query
            } finally {
                if (stats != null) {
                    try {
                        stats.close();
                    } catch (Exception ignored) {
                        // closing a read-only cursor; nothing to recover
                    }
                }
            }
        }

        for (AppUse use : byUid.values()) {
            resolve(ctx, use);
            result.apps.add(use);
        }
        Collections.sort(result.apps, new Comparator<AppUse>() {
            @Override
            public int compare(AppUse a, AppUse b) {
                return Long.compare(b.total(), a.total());
            }
        });
        while (result.apps.size() > 40) {
            result.apps.remove(result.apps.size() - 1);
        }
        if (result.apps.isEmpty()) {
            result.note = "No app traffic in the last " + (windowMs / 60000) + " min.";
        }
        return result;
    }

    private static void resolve(Context ctx, AppUse use) {
        String pkg = PKGS.get(use.uid);
        if (pkg == null) {
            if (use.uid == 0) {
                pkg = "root";
            } else if (use.uid == 1000) {
                pkg = "android";
            } else {
                try {
                    String[] names = ctx.getPackageManager().getPackagesForUid(use.uid);
                    pkg = (names != null && names.length > 0) ? names[0] : "";
                } catch (Exception e) {
                    pkg = "";
                }
            }
            if (PKGS.size() > 400) PKGS.clear();
            PKGS.put(use.uid, pkg);
        }
        use.pkg = pkg;
        use.key = pkg.isEmpty() ? ("uid " + use.uid) : pkg;

        String label = LABELS.get(use.uid);
        if (label == null) {
            label = pkg;
            try {
                PackageManager pm = ctx.getPackageManager();
                ApplicationInfo info = pm.getApplicationInfo(pkg, 0);
                CharSequence text = pm.getApplicationLabel(info);
                if (text != null && text.length() > 0) label = text.toString();
            } catch (Exception ignored) {
                // unknown package: fall back to the package name
            }
            if (label == null || label.isEmpty()) label = "uid " + use.uid;
            if (LABELS.size() > 400) LABELS.clear();
            LABELS.put(use.uid, label);
        }
        use.label = label;
    }
}
