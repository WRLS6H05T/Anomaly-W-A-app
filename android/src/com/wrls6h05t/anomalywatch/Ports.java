package com.wrls6h05t.anomalywatch;

import java.util.HashMap;
import java.util.Map;

/**
 * Port knowledge base: which services are encrypted, which are clear text, and
 * how bad it is when they are not. Mirrors lib/classify.js on the desktop build.
 */
final class Ports {

    static final class Info {
        final String service;
        final String mode;      // "encrypted" | "plaintext" | "unknown"
        final String severity;  // null unless mode is plaintext
        final int rank;         // 1..4, 4 = critical
        final String why;
        final boolean known;

        Info(String service, String mode, String severity, String why, boolean known) {
            this.service = service;
            this.mode = mode;
            this.severity = severity;
            this.rank = rankOf(severity);
            this.why = why;
            this.known = known;
        }
    }

    private static final Map<Integer, Info> TABLE = new HashMap<>();

    private static int rankOf(String severity) {
        if (severity == null) return 0;
        if ("critical".equals(severity)) return 4;
        if ("high".equals(severity)) return 3;
        if ("medium".equals(severity)) return 2;
        return 1;
    }

    private static void put(int port, String service, String mode, String severity, String why) {
        if ("plaintext".equals(mode) && severity == null) severity = "medium";
        TABLE.put(port, new Info(service, mode, "plaintext".equals(mode) ? severity : null, why, true));
    }

    static {
        put(20, "FTP data", "plaintext", "high", "FTP moves files with no encryption.");
        put(21, "FTP", "plaintext", "high", "FTP sends credentials and files in clear text.");
        put(22, "SSH", "encrypted", null, "Encrypted transport.");
        put(23, "Telnet", "plaintext", "critical", "Telnet sends keystrokes and credentials in clear text.");
        put(25, "SMTP", "plaintext", "high", "Mail is relayed in clear text unless STARTTLS is negotiated.");
        put(53, "DNS", "plaintext", "medium", "DNS lookups are unencrypted and reveal every site you visit.");
        put(67, "DHCP", "plaintext", "low", "DHCP has no encryption or authentication.");
        put(68, "DHCP", "plaintext", "low", "DHCP has no encryption or authentication.");
        put(69, "TFTP", "plaintext", "high", "TFTP transfers files with no encryption or authentication.");
        put(80, "HTTP", "plaintext", "high", "HTTP sends the entire request and response in clear text.");
        put(110, "POP3", "plaintext", "high", "POP3 without TLS sends credentials and mail in clear text.");
        put(111, "rpcbind", "plaintext", "medium", "RPC portmapper exposes service listings in clear text.");
        put(123, "NTP", "plaintext", "low", "NTP is unauthenticated; responses can be spoofed.");
        put(135, "MS RPC", "plaintext", "medium", "Windows RPC endpoint mapper is unencrypted.");
        put(137, "NetBIOS-NS", "plaintext", "medium", "NetBIOS name service leaks host and workgroup names.");
        put(139, "NetBIOS-SSN", "plaintext", "medium", "NetBIOS session service has no encryption.");
        put(143, "IMAP", "plaintext", "high", "IMAP without TLS sends credentials and mail in clear text.");
        put(161, "SNMP", "plaintext", "high", "SNMPv1/v2 community strings travel unencrypted.");
        put(389, "LDAP", "plaintext", "high", "LDAP without LDAPS sends directory credentials in clear text.");
        put(443, "HTTPS", "encrypted", null, "TLS-protected transport.");
        put(445, "SMB", "plaintext", "medium", "SMB without signing or encryption exposes file shares.");
        put(465, "SMTPS", "encrypted", null, "Implicit TLS.");
        put(500, "IPsec IKE", "encrypted", null, "IPsec key exchange.");
        put(513, "rlogin", "plaintext", "critical", "rlogin sends credentials in clear text.");
        put(514, "syslog", "plaintext", "low", "Syslog messages are unencrypted.");
        put(587, "SMTP submission", "encrypted", null, "STARTTLS-negotiated mail submission.");
        put(631, "IPP", "plaintext", "low", "Print jobs are submitted unencrypted.");
        put(636, "LDAPS", "encrypted", null, "TLS-protected directory access.");
        put(853, "DoT", "encrypted", null, "DNS over TLS.");
        put(873, "rsync", "plaintext", "medium", "rsync modules transfer files unencrypted.");
        put(990, "FTPS", "encrypted", null, "Implicit TLS file transfer.");
        put(993, "IMAPS", "encrypted", null, "TLS-protected mail access.");
        put(995, "POP3S", "encrypted", null, "TLS-protected mail access.");
        put(1080, "SOCKS proxy", "unknown", null, "Encryption depends on the proxied traffic.");
        put(1194, "OpenVPN", "encrypted", null, "VPN tunnel.");
        put(1433, "MSSQL", "plaintext", "high", "SQL Server logins are exposed without forced TLS.");
        put(1900, "SSDP", "plaintext", "low", "Device discovery broadcasts are unencrypted.");
        put(2049, "NFS", "plaintext", "medium", "NFS traffic is unauthenticated unless Kerberos is used.");
        put(2375, "Docker API", "plaintext", "critical", "Unauthenticated Docker API reachable in clear text.");
        put(2376, "Docker TLS", "encrypted", null, "TLS-protected Docker API.");
        put(3000, "HTTP (dev)", "plaintext", "medium", "Development HTTP server without TLS.");
        put(3306, "MySQL", "plaintext", "high", "MySQL handshake exposes credentials in clear text.");
        put(3389, "RDP", "encrypted", null, "RDP is encrypted, though the protocol has a weak history.");
        put(3478, "STUN/TURN", "plaintext", "low", "NAT traversal traffic is unencrypted.");
        put(4500, "IPsec NAT-T", "encrypted", null, "IPsec key exchange.");
        put(5060, "SIP", "plaintext", "high", "SIP signalling carries credentials in clear text.");
        put(5061, "SIP-TLS", "encrypted", null, "TLS-protected SIP.");
        put(5222, "XMPP", "plaintext", "medium", "XMPP is unencrypted until STARTTLS.");
        put(5223, "Apple push", "encrypted", null, "TLS-protected notification channel.");
        put(5228, "Google push", "encrypted", null, "TLS-protected notification channel.");
        put(5353, "mDNS", "plaintext", "low", "Local discovery broadcasts are unencrypted.");
        put(5355, "LLMNR", "plaintext", "low", "LLMNR name lookups are unauthenticated.");
        put(5432, "PostgreSQL", "plaintext", "high", "PostgreSQL logins are exposed without sslmode=require.");
        put(5672, "AMQP", "plaintext", "high", "AMQP sends broker credentials in clear text.");
        put(5900, "VNC", "plaintext", "critical", "VNC sends the session and password in clear text.");
        put(5985, "WinRM", "plaintext", "high", "WinRM over HTTP exposes admin credentials.");
        put(5986, "WinRM TLS", "encrypted", null, "TLS-protected remote management.");
        put(6379, "Redis", "plaintext", "high", "Redis has no transport encryption by default.");
        put(6443, "Kubernetes API", "encrypted", null, "TLS-protected control plane.");
        put(8000, "HTTP alt", "plaintext", "high", "Plain HTTP on an alternate port.");
        put(8080, "HTTP alt", "plaintext", "high", "Plain HTTP on an alternate port.");
        put(8081, "HTTP alt", "plaintext", "high", "Plain HTTP on an alternate port.");
        put(8443, "HTTPS alt", "encrypted", null, "TLS-protected transport.");
        put(8883, "MQTTS", "encrypted", null, "TLS-protected MQTT.");
        put(9092, "Kafka", "plaintext", "medium", "Kafka traffic is unencrypted without TLS listeners.");
        put(9200, "Elasticsearch", "plaintext", "high", "Elasticsearch HTTP API is unauthenticated and unencrypted by default.");
        put(9300, "ES transport", "plaintext", "high", "Elasticsearch node transport is unencrypted.");
        put(9418, "git", "plaintext", "medium", "The git:// protocol has no encryption or authentication.");
        put(11211, "Memcached", "plaintext", "high", "Memcached has no transport encryption.");
        put(27017, "MongoDB", "plaintext", "high", "MongoDB is unencrypted unless TLS is configured.");
        put(51820, "WireGuard", "encrypted", null, "VPN tunnel.");
    }

    private Ports() {
    }

    static Info classify(int port, String proto) {
        Info entry = TABLE.get(port);
        if (entry != null) {
            if ("udp".equals(proto) && port == 443) {
                return new Info("QUIC", "encrypted", null, "QUIC is TLS 1.3 encrypted.", true);
            }
            return entry;
        }
        if (port <= 0) {
            return new Info("—", "unknown", null, "No remote port recorded.", false);
        }
        String service = port < 1024 ? "unrecognized system port" : "unrecognized port";
        return new Info(service, "unknown", null,
                "Port is not in the protocol knowledge base, so encryption cannot be confirmed.", false);
    }

    static boolean isLoopback(String host) {
        if (host == null || host.isEmpty()) return false;
        return "::1".equals(host)
                || "::".equals(host)
                || "0.0.0.0".equals(host)
                || "*".equals(host)
                || "0:0:0:0:0:0:0:1".equals(host)
                || host.startsWith("127.");
    }

    static boolean isPrivateIp(String host) {
        if (host == null || host.isEmpty() || "*".equals(host) || "0.0.0.0".equals(host) || "::".equals(host)) return true;
        if (host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.")
                || host.startsWith("169.254.")) {
            return true;
        }
        if (host.startsWith("172.")) {
            int dot = host.indexOf('.', 4);
            if (dot > 4) {
                try {
                    int second = Integer.parseInt(host.substring(4, dot));
                    if (second >= 16 && second <= 31) return true;
                } catch (NumberFormatException ignored) {
                    // fall through
                }
            }
        }
        String lower = host.toLowerCase();
        return lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80:");
    }
}
