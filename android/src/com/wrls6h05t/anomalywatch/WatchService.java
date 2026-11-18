package com.wrls6h05t.anomalywatch;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Keeps the monitor running while the app is in the background. */
public class WatchService extends Service {

    static final String CH_STATUS = "aw_status";
    static final String CH_ALERTS = "aw_alerts";
    private static final int FG_ID = 1001;
    private static final long POLL_MS = 4000;

    static volatile boolean RUNNING;

    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private boolean scheduled;

    private final Runnable poll = new Runnable() {
        @Override
        public void run() {
            tick();
            main.postDelayed(this, POLL_MS);
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        RUNNING = true;
        createChannels();
        startForegroundCompat(buildStatus("Starting…"));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (!scheduled) {
            scheduled = true;
            tick();
            main.postDelayed(poll, POLL_MS);
        }
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        RUNNING = false;
        main.removeCallbacks(poll);
        io.shutdownNow();
        super.onDestroy();
    }

    private void tick() {
        io.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    Monitor.get(WatchService.this).tick();
                } catch (Throwable t) {
                    Log.w("anomalywatch", "scan failed", t);
                }
                main.post(new Runnable() {
                    @Override
                    public void run() {
                        afterTick();
                    }
                });
            }
        });
    }

    private void afterTick() {
        Monitor monitor = Monitor.get(this);
        Monitor.Snapshot s = monitor.snapshot();
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm == null) return;

        nm.notify(FG_ID, buildStatus(s.total + " connections · " + s.unverified + " unverified · "
                + s.alerts.size() + " alerts"));

        List<Monitor.Alert> fresh = monitor.drainNewAlerts();
        for (Monitor.Alert a : fresh) {
            if (!"high".equals(a.severity) && !"critical".equals(a.severity)) continue;
            nm.notify(2000 + Math.abs(a.id.hashCode() % 2000), buildAlert(a));
        }
    }

    private void createChannels() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm == null) return;
        nm.createNotificationChannel(
                new NotificationChannel(CH_STATUS, "Watching", NotificationManager.IMPORTANCE_LOW));
        NotificationChannel alerts =
                new NotificationChannel(CH_ALERTS, "Alerts", NotificationManager.IMPORTANCE_HIGH);
        alerts.setDescription("Unverified activity and unencrypted traffic");
        nm.createNotificationChannel(alerts);
    }

    private PendingIntent openApp() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) flags |= PendingIntent.FLAG_IMMUTABLE;
        return PendingIntent.getActivity(this, 0, intent, flags);
    }

    private Notification buildStatus(String text) {
        Notification.Builder b = new Notification.Builder(this, CH_STATUS)
                .setSmallIcon(R.drawable.ic_launcher)
                .setContentTitle("Anomaly Watch")
                .setContentText(text)
                .setContentIntent(openApp())
                .setOngoing(true)
                .setOnlyAlertOnce(true);
        return b.build();
    }

    private Notification buildAlert(Monitor.Alert a) {
        Notification.Builder b = new Notification.Builder(this, CH_ALERTS)
                .setSmallIcon(R.drawable.ic_launcher)
                .setContentTitle(a.title)
                .setContentText(a.detail)
                .setStyle(new Notification.BigTextStyle().bigText(a.detail))
                .setContentIntent(openApp())
                .setAutoCancel(true);
        return b.build();
    }

    private void startForegroundCompat(Notification n) {
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(FG_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(FG_ID, n);
        }
    }
}
