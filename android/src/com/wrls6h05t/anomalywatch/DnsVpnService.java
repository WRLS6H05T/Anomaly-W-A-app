package com.wrls6h05t.anomalywatch;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The kernel socket table is closed to apps, so the only way to observe real
 * traffic is to become the network's DNS resolver.
 *
 * Traffic is NOT routed through the tunnel: the only route added is the fake
 * resolver address, so just the system's DNS queries come here. Each query is
 * forwarded to the real resolver over a protected socket and the reply is
 * written back, which keeps name resolution working while recording every
 * lookup made in clear text.
 */
public class DnsVpnService extends VpnService {

    static volatile boolean RUNNING;

    /** Sent from the dashboard: a foreground service has to stop itself. */
    static final String ACTION_STOP = "com.wrls6h05t.anomalywatch.STOP_DNS_CAPTURE";

    private static final int FG_ID = 1002;
    private static final String CH_DNS = "aw_dns";

    private static final String TUN_IP = "10.111.222.1";
    private static final String TUN_DNS = "10.111.222.2";
    private static final int DNS_PORT = 53;

    private ParcelFileDescriptor tun;
    private volatile boolean running;
    private Thread pumpThread;
    private final ExecutorService pool = Executors.newFixedThreadPool(4);
    private int lookups;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            Log.d("anomalywatch", "dns capture: stop requested by the dashboard");
            stopCapture();
            return START_NOT_STICKY;
        }
        // START_STICKY resurrects the service after it dies, including after the
        // user pressed Stop; that opt-out has to win over the restart.
        if (getSharedPreferences("aw", MODE_PRIVATE).getBoolean("dns_stopped", false)) {
            Log.d("anomalywatch", "dns capture: stopped by the user, not restarting");
            stopSelf();
            return START_NOT_STICKY;
        }
        if (running) return START_STICKY;
        List<String> upstream = upstreamServers();
        if (upstream.isEmpty()) {
            Log.w("anomalywatch", "dns capture: no upstream resolver found");
            stopSelf();
            return START_NOT_STICKY;
        }
        try {
            Builder builder = new Builder();
            builder.setSession("Anomaly Watch DNS");
            builder.addAddress(TUN_IP, 32);
            // Advertise a resolver that lives inside the tunnel. Android's own
            // resolver bypasses routes to the real servers, so this is the only
            // way its queries reach us; everything except DNS keeps its path.
            builder.addDnsServer(TUN_DNS);
            builder.addRoute(TUN_DNS, 32);
            builder.setMtu(1500);
            builder.setBlocking(true);
            tun = builder.establish();
        } catch (Exception e) {
            Log.w("anomalywatch", "dns capture: could not establish tunnel", e);
            tun = null;
        }
        if (tun == null) {
            stopSelf();
            return START_NOT_STICKY;
        }
        running = true;
        RUNNING = true;
        startCaptureNotification();
        pumpThread = new Thread(new Runnable() {
            @Override
            public void run() {
                pump();
            }
        }, "dns-capture");
        pumpThread.start();
        Monitor.get(this).captureStarted();
        return START_STICKY;
    }

    private void stopCapture() {
        running = false;
        RUNNING = false;
        if (tun != null) {
            try {
                tun.close();
            } catch (Exception ignored) {
                // already closing
            }
            tun = null;
        }
        stopForeground(true);
        stopSelf();
    }

    /** Pins the capture in the shade, otherwise Android reaps it once the app is closed. */
    private void startCaptureNotification() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm == null) return;
        NotificationChannel channel = new NotificationChannel(CH_DNS, "DNS capture",
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Keeps the plaintext DNS capture alive while the app is closed");
        nm.createNotificationChannel(channel);
        try {
            startForeground(FG_ID, captureNotification(0));
        } catch (Exception e) {
            // Some builds refuse the declared foreground type. The tunnel keeps
            // working while the app is open, it just is not pinned.
            Log.w("anomalywatch", "dns capture: startForeground refused", e);
        }
    }

    private Notification captureNotification(int count) {
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) flags |= PendingIntent.FLAG_IMMUTABLE;
        PendingIntent pending = PendingIntent.getActivity(this, 0, open, flags);
        return new Notification.Builder(this, CH_DNS)
                .setSmallIcon(R.drawable.ic_launcher)
                .setContentTitle("Anomaly Watch · DNS capture")
                .setContentText(count == 0 ? "Recording plaintext lookups"
                        : count + " lookups recorded")
                .setContentIntent(pending)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .build();
    }

    /** Another VPN or the system took the tunnel away: report it instead of pretending. */
    @Override
    public void onRevoke() {
        Log.w("anomalywatch", "dns capture: revoked");
        running = false;
        RUNNING = false;
        stopSelf();
    }

    @Override
    public void onDestroy() {
        Log.d("anomalywatch", "dns capture: service destroyed");
        running = false;
        RUNNING = false;
        stopForeground(true);
        if (tun != null) {
            try {
                tun.close();
            } catch (Exception ignored) {
                // closing the tun; nothing to recover
            }
            tun = null;
        }
        pool.shutdownNow();
        super.onDestroy();
    }

    /* --------------------------------------------------------------- capture */

    private void pump() {
        FileInputStream in = new FileInputStream(tun.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(tun.getFileDescriptor());
        byte[] buffer = new byte[32767];
        while (running) {
            int length;
            try {
                length = in.read(buffer);
            } catch (Exception e) {
                break;
            }
            if (length <= 0) continue;
            final byte[] packet = new byte[length];
            System.arraycopy(buffer, 0, packet, 0, length);
            final List<String> upstream = upstreamServers();
            if (upstream.isEmpty()) continue;
            try {
                pool.execute(new Runnable() {
                    @Override
                    public void run() {
                        handle(packet, upstream, out);
                    }
                });
            } catch (Exception ignored) {
                // pool shutting down
            }
        }
    }

    private void handle(byte[] packet, List<String> upstream, FileOutputStream out) {
        try {
            if (packet.length < 28 || (packet[0] >> 4) != 4) return;
            int ihl = (packet[0] & 0x0F) * 4;
            if (ihl < 20 || packet.length < ihl + 8) return;
            if ((packet[9] & 0xFF) != 17) return;

            int totalLength = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
            if (totalLength > packet.length) totalLength = packet.length;

            int srcPort = ((packet[ihl] & 0xFF) << 8) | (packet[ihl + 1] & 0xFF);
            int dstPort = ((packet[ihl + 2] & 0xFF) << 8) | (packet[ihl + 3] & 0xFF);
            if (dstPort != DNS_PORT) return;

            int payloadOffset = ihl + 8;
            int payloadLength = totalLength - payloadOffset;
            if (payloadLength <= 0) return;

            byte[] query = new byte[payloadLength];
            System.arraycopy(packet, payloadOffset, query, 0, payloadLength);
            String domain = questionName(query);
            if (domain.isEmpty()) return;

            byte[] reply = forward(query, upstream);
            if (reply == null) {
                Log.w("anomalywatch", "dns forward failed for " + domain);
                return;
            }

            byte[] response = buildResponse(packet, ihl, srcPort, reply);
            if (response == null) return;
            synchronized (out) {
                out.write(response);
            }

            // Reverse lookups are noise in a per-app view; forward them, don't list them.
            boolean recordable = !domain.endsWith(".in-addr.arpa") && !domain.endsWith(".ip6.arpa");
            if (recordable) {
                String app = ownerName(packet, ihl, srcPort);
                Log.d("anomalywatch", "dns " + domain + " from " + app);
                Monitor.get(this).recordDns(domain, app, upstream.get(0));
                updateNotification();
            }
        } catch (Exception ignored) {
            // malformed packet: drop it, the client will retry
        }
    }

    private synchronized void updateNotification() {
        if (++lookups % 20 != 0) return;
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(FG_ID, captureNotification(lookups));
    }

    private byte[] forward(byte[] query, List<String> upstream) {
        for (String server : upstream) {
            DatagramSocket socket = null;
            try {
                socket = new DatagramSocket();
                protect(socket);
                socket.setSoTimeout(2500);
                InetAddress address = InetAddress.getByName(server);
                socket.send(new DatagramPacket(query, query.length, address, DNS_PORT));
                byte[] buffer = new byte[4096];
                DatagramPacket reply = new DatagramPacket(buffer, buffer.length);
                socket.receive(reply);
                byte[] data = new byte[reply.getLength()];
                System.arraycopy(buffer, 0, data, 0, reply.getLength());
                return data;
            } catch (Exception e) {
                // try the next resolver
            } finally {
                if (socket != null) socket.close();
            }
        }
        return null;
    }

    /** Rebuilds the request as a reply: swap addresses and ports, keep the payload. */
    private byte[] buildResponse(byte[] request, int ihl, int clientPort, byte[] payload) {
        int total = 20 + 8 + payload.length;
        byte[] packet = new byte[total];

        packet[0] = 0x45;
        packet[1] = 0;
        packet[2] = (byte) ((total >> 8) & 0xFF);
        packet[3] = (byte) (total & 0xFF);
        packet[4] = 0;
        packet[5] = 0;
        packet[6] = 0x40; // don't fragment
        packet[7] = 0;
        packet[8] = 64;
        packet[9] = 17;
        // source = the fake resolver, destination = whoever asked
        packet[12] = request[16];
        packet[13] = request[17];
        packet[14] = request[18];
        packet[15] = request[19];
        packet[16] = request[12];
        packet[17] = request[13];
        packet[18] = request[14];
        packet[19] = request[15];

        int checksum = ipChecksum(packet, 20);
        packet[10] = (byte) ((checksum >> 8) & 0xFF);
        packet[11] = (byte) (checksum & 0xFF);

        packet[20] = (byte) ((DNS_PORT >> 8) & 0xFF);
        packet[21] = (byte) (DNS_PORT & 0xFF);
        packet[22] = (byte) ((clientPort >> 8) & 0xFF);
        packet[23] = (byte) (clientPort & 0xFF);
        int udpLength = 8 + payload.length;
        packet[24] = (byte) ((udpLength >> 8) & 0xFF);
        packet[25] = (byte) (udpLength & 0xFF);
        packet[26] = 0; // checksum optional for IPv4 UDP
        packet[27] = 0;

        System.arraycopy(payload, 0, packet, 28, payload.length);
        return packet;
    }

    private static int ipChecksum(byte[] header, int length) {
        long sum = 0;
        for (int i = 0; i < length; i += 2) {
            sum += ((header[i] & 0xFF) << 8) | (header[i + 1] & 0xFF);
        }
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    /** Reads the first question name out of a DNS query. */
    static String questionName(byte[] dns) {
        if (dns == null || dns.length < 13) return "";
        StringBuilder name = new StringBuilder();
        int index = 12;
        while (index < dns.length) {
            int length = dns[index] & 0xFF;
            if (length == 0) break;
            if ((length & 0xC0) != 0) break;
            index++;
            if (index + length > dns.length) break;
            if (name.length() > 0) name.append('.');
            name.append(new String(dns, index, length, StandardCharsets.ISO_8859_1));
            index += length;
            if (name.length() > 200) break;
        }
        return name.toString();
    }

    /* ------------------------------------------------------------------ peers */

    private String ownerName(byte[] packet, int ihl, int srcPort) {
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                ConnectivityManager cm =
                        (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    InetAddress local = InetAddress.getByAddress(new byte[]{
                            packet[12], packet[13], packet[14], packet[15]});
                    InetAddress remote = InetAddress.getByAddress(new byte[]{
                            packet[16], packet[17], packet[18], packet[19]});
                    int uid = cm.getConnectionOwnerUid(17,
                            new InetSocketAddress(local, srcPort),
                            new InetSocketAddress(remote, DNS_PORT));
                    if (uid > 0) {
                        String[] packages = getPackageManager().getPackagesForUid(uid);
                        if (packages != null && packages.length > 0) return packages[0];
                        return "uid " + uid;
                    }
                }
            }
        } catch (Exception ignored) {
            // attribution is best effort
        }
        return "system resolver";
    }

    /** The real resolvers, read from the network underneath the tunnel. */
    private List<String> upstreamServers() {
        List<String> servers = new ArrayList<>();
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return servers;
            for (Network network : cm.getAllNetworks()) {
                NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                if (caps == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                LinkProperties lp = cm.getLinkProperties(network);
                if (lp == null || lp.getDnsServers() == null) continue;
                for (InetAddress address : lp.getDnsServers()) {
                    if (address.getAddress().length == 4) {
                        String host = address.getHostAddress();
                        if (!servers.contains(host)) servers.add(host);
                    }
                }
                if (!servers.isEmpty()) break;
            }
        } catch (Exception ignored) {
            // fall through with whatever was found
        }
        if (servers.isEmpty()) servers.add("8.8.8.8");
        return servers;
    }
}
