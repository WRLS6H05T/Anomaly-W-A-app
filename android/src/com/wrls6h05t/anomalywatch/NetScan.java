package com.wrls6h05t.anomalywatch;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads the kernel socket tables. On most Android builds /proc/net/tcp is
 * readable, but it may only contain this app's own sockets (the platform
 * filters by UID). Whatever is visible is reported honestly.
 */
final class NetScan {

    static final class Sock {
        String proto;
        String state;
        String localIp;
        String remoteIp;
        int localPort;
        int remotePort;
        int uid;
        boolean listener;

        String id() {
            return proto + "|" + localIp + ":" + localPort + "|" + remoteIp + ":" + remotePort
                    + "|" + state + "|" + uid;
        }
    }

    static final class Result {
        final List<Sock> socks;
        final String error;

        Result(List<Sock> socks, String error) {
            this.socks = socks;
            this.error = error;
        }
    }

    private static final String[] FILES = {
            "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"
    };

    private NetScan() {
    }

    static Result read() {
        List<Sock> socks = new ArrayList<>();
        int readable = 0;
        for (String path : FILES) {
            try {
                parse(path, socks);
                readable++;
            } catch (Exception ignored) {
                // file missing or blocked — keep going
            }
        }
        String error = readable == 0
                ? "Android blocked the socket table (/proc/net/* is unreadable on this device)."
                : null;
        return new Result(socks, error);
    }

    private static void parse(String path, List<Sock> out) throws Exception {
        String proto = path.contains("udp") ? "udp" : "tcp";
        BufferedReader reader = new BufferedReader(new FileReader(path));
        try {
            reader.readLine(); // header
            String line;
            while ((line = reader.readLine()) != null) {
                String row = line.trim();
                if (row.isEmpty()) continue;
                String[] p = row.split("\\s+");
                if (p.length < 10) continue;

                int li = p[1].lastIndexOf(':');
                int ri = p[2].lastIndexOf(':');
                if (li < 0 || ri < 0) continue;

                int localPort = hex(p[1].substring(li + 1));
                int remotePort = hex(p[2].substring(ri + 1));
                if (localPort <= 0 && remotePort <= 0) continue;

                String state = tcpState(p[3]);
                if ("TIME_WAIT".equals(state) || "CLOSE_WAIT".equals(state)) continue;

                Sock s = new Sock();
                s.proto = proto;
                s.state = state;
                s.localIp = addr(p[1].substring(0, li));
                s.remoteIp = addr(p[2].substring(0, ri));
                s.localPort = localPort;
                s.remotePort = remotePort;
                s.uid = parseInt(p[7], -1);
                s.listener = "LISTEN".equals(state) || ("BOUND".equals(state) && remotePort == 0);
                out.add(s);
            }
        } finally {
            reader.close();
        }
    }

    private static int parseInt(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static int hex(String value) {
        try {
            return Integer.parseInt(value, 16);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String tcpState(String code) {
        switch (code) {
            case "01": return "ESTABLISHED";
            case "02": return "SYN_SENT";
            case "03": return "SYN_RECV";
            case "04": return "FIN_WAIT1";
            case "05": return "FIN_WAIT2";
            case "06": return "TIME_WAIT";
            case "07": return "BOUND";
            case "08": return "CLOSE_WAIT";
            case "09": return "LAST_ACK";
            case "0A": return "LISTEN";
            case "0B": return "CLOSING";
            default: return "UNKNOWN";
        }
    }

    /** /proc encodes addresses as 4-byte little-endian words in hex. */
    private static String addr(String hex) {
        try {
            int len = hex.length() / 2;
            if (len < 4 || len > 16 || hex.length() % 8 != 0) return hex;
            byte[] bytes = new byte[len];
            for (int word = 0; word + 8 <= hex.length(); word += 8) {
                for (int b = 0; b < 4; b++) {
                    int hi = Character.digit(hex.charAt(word + b * 2), 16);
                    int lo = Character.digit(hex.charAt(word + b * 2 + 1), 16);
                    if (hi < 0 || lo < 0) return hex;
                    bytes[word / 2 + (3 - b)] = (byte) ((hi << 4) | lo);
                }
            }
            return InetAddress.getByAddress(bytes).getHostAddress();
        } catch (Exception e) {
            return hex;
        }
    }
}
