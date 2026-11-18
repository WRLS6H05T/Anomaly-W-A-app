'use strict';

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Port knowledge base.
 * mode: 'encrypted' | 'plaintext' | 'unknown'
 * severity: risk if the traffic is unencrypted (null = not flagged)
 * Per-protocol overrides live on the `udp` / `tcp` keys.
 */
const PORTS = {
  20: { service: 'FTP data', mode: 'plaintext', severity: 'high', why: 'FTP moves files with no encryption.' },
  21: { service: 'FTP', mode: 'plaintext', severity: 'high', why: 'FTP sends credentials and files in clear text.' },
  22: { service: 'SSH', mode: 'encrypted', severity: null, why: 'Encrypted transport.' },
  23: { service: 'Telnet', mode: 'plaintext', severity: 'critical', why: 'Telnet sends keystrokes and credentials in clear text.' },
  25: { service: 'SMTP', mode: 'plaintext', severity: 'high', why: 'Mail is relayed in clear text unless STARTTLS is negotiated.' },
  53: { service: 'DNS', mode: 'plaintext', severity: 'medium', why: 'DNS lookups are unencrypted and reveal every site you visit.' },
  67: { service: 'DHCP', mode: 'plaintext', severity: 'low', why: 'DHCP has no encryption or authentication.' },
  68: { service: 'DHCP', mode: 'plaintext', severity: 'low', why: 'DHCP has no encryption or authentication.' },
  69: { service: 'TFTP', mode: 'plaintext', severity: 'high', why: 'TFTP transfers files with no encryption or authentication.' },
  80: { service: 'HTTP', mode: 'plaintext', severity: 'high', why: 'HTTP sends the entire request and response in clear text.' },
  110: { service: 'POP3', mode: 'plaintext', severity: 'high', why: 'POP3 without TLS sends credentials and mail in clear text.' },
  111: { service: 'rpcbind', mode: 'plaintext', severity: 'medium', why: 'RPC portmapper exposes service listings in clear text.' },
  119: { service: 'NNTP', mode: 'plaintext', severity: 'low', why: 'Usenet traffic is unencrypted.' },
  123: { service: 'NTP', mode: 'plaintext', severity: 'low', why: 'NTP is unauthenticated; responses can be spoofed.' },
  135: { service: 'MS RPC', mode: 'plaintext', severity: 'medium', why: 'Windows RPC endpoint mapper is unencrypted.' },
  137: { service: 'NetBIOS-NS', mode: 'plaintext', severity: 'medium', why: 'NetBIOS name service leaks host and workgroup names.' },
  138: { service: 'NetBIOS-DGM', mode: 'plaintext', severity: 'medium', why: 'NetBIOS datagrams are unencrypted.' },
  139: { service: 'NetBIOS-SSN', mode: 'plaintext', severity: 'medium', why: 'NetBIOS session service has no encryption.' },
  143: { service: 'IMAP', mode: 'plaintext', severity: 'high', why: 'IMAP without TLS sends credentials and mail in clear text.' },
  161: { service: 'SNMP', mode: 'plaintext', severity: 'high', why: 'SNMPv1/v2 community strings travel unencrypted.' },
  162: { service: 'SNMP trap', mode: 'plaintext', severity: 'medium', why: 'SNMP traps are unencrypted.' },
  179: { service: 'BGP', mode: 'plaintext', severity: 'low', why: 'BGP sessions are unencrypted without TCP-MD5.' },
  389: { service: 'LDAP', mode: 'plaintext', severity: 'high', why: 'LDAP without LDAPS sends directory credentials in clear text.' },
  443: {
    service: 'HTTPS',
    mode: 'encrypted',
    severity: null,
    why: 'TLS-protected transport.',
    udp: { service: 'QUIC', mode: 'encrypted', severity: null, why: 'QUIC is TLS 1.3 encrypted.' }
  },
  445: { service: 'SMB', mode: 'plaintext', severity: 'medium', why: 'SMB without signing or encryption exposes file shares.' },
  465: { service: 'SMTPS', mode: 'encrypted', severity: null, why: 'Implicit TLS.' },
  500: { service: 'IPsec IKE', mode: 'encrypted', severity: null, why: 'IPsec key exchange.' },
  513: { service: 'rlogin', mode: 'plaintext', severity: 'critical', why: 'rlogin sends credentials in clear text.' },
  514: { service: 'syslog', mode: 'plaintext', severity: 'low', why: 'Syslog messages are unencrypted.' },
  587: { service: 'SMTP submission', mode: 'encrypted', severity: null, why: 'STARTTLS-negotiated mail submission.' },
  631: { service: 'IPP', mode: 'plaintext', severity: 'low', why: 'Print jobs are submitted unencrypted.' },
  636: { service: 'LDAPS', mode: 'encrypted', severity: null, why: 'TLS-protected directory access.' },
  853: { service: 'DoT', mode: 'encrypted', severity: null, why: 'DNS over TLS.' },
  873: { service: 'rsync', mode: 'plaintext', severity: 'medium', why: 'rsync modules transfer files unencrypted.' },
  990: { service: 'FTPS', mode: 'encrypted', severity: null, why: 'Implicit TLS file transfer.' },
  993: { service: 'IMAPS', mode: 'encrypted', severity: null, why: 'TLS-protected mail access.' },
  995: { service: 'POP3S', mode: 'encrypted', severity: null, why: 'TLS-protected mail access.' },
  1080: { service: 'SOCKS proxy', mode: 'unknown', severity: null, why: 'Encryption depends on the proxied traffic.' },
  1194: { service: 'OpenVPN', mode: 'encrypted', severity: null, why: 'VPN tunnel.' },
  1433: { service: 'MSSQL', mode: 'plaintext', severity: 'high', why: 'SQL Server logins are exposed without forced TLS.' },
  1900: { service: 'SSDP', mode: 'plaintext', severity: 'low', why: 'Device discovery broadcasts are unencrypted.' },
  2049: { service: 'NFS', mode: 'plaintext', severity: 'medium', why: 'NFS traffic is unauthenticated unless Kerberos is used.' },
  2375: { service: 'Docker API', mode: 'plaintext', severity: 'critical', why: 'Unauthenticated Docker API reachable in clear text.' },
  2376: { service: 'Docker TLS', mode: 'encrypted', severity: null, why: 'TLS-protected Docker API.' },
  3000: { service: 'HTTP (dev)', mode: 'plaintext', severity: 'medium', why: 'Development HTTP server without TLS.' },
  3306: { service: 'MySQL', mode: 'plaintext', severity: 'high', why: 'MySQL handshake exposes credentials in clear text.' },
  3389: { service: 'RDP', mode: 'encrypted', severity: null, why: 'RDP is encrypted, though the protocol has a weak history.' },
  3478: { service: 'STUN/TURN', mode: 'plaintext', severity: 'low', why: 'NAT traversal traffic is unencrypted.' },
  4500: { service: 'IPsec NAT-T', mode: 'encrypted', severity: null, why: 'IPsec key exchange.' },
  5000: { service: 'HTTP (dev)', mode: 'plaintext', severity: 'medium', why: 'Development HTTP server without TLS.' },
  5060: { service: 'SIP', mode: 'plaintext', severity: 'high', why: 'SIP signalling carries credentials in clear text.' },
  5061: { service: 'SIP-TLS', mode: 'encrypted', severity: null, why: 'TLS-protected SIP.' },
  5173: { service: 'HTTP (dev)', mode: 'plaintext', severity: 'medium', why: 'Development HTTP server without TLS.' },
  5222: { service: 'XMPP', mode: 'plaintext', severity: 'medium', why: 'XMPP is unencrypted until STARTTLS.' },
  5223: { service: 'Apple push', mode: 'encrypted', severity: null, why: 'TLS-protected notification channel.' },
  5228: { service: 'Google push', mode: 'encrypted', severity: null, why: 'TLS-protected notification channel.' },
  5353: { service: 'mDNS', mode: 'plaintext', severity: 'low', why: 'Local discovery broadcasts are unencrypted.' },
  5355: { service: 'LLMNR', mode: 'plaintext', severity: 'low', why: 'LLMNR name lookups are unauthenticated.' },
  5432: { service: 'PostgreSQL', mode: 'plaintext', severity: 'high', why: 'PostgreSQL logins are exposed without sslmode=require.' },
  5672: { service: 'AMQP', mode: 'plaintext', severity: 'high', why: 'AMQP sends broker credentials in clear text.' },
  5900: { service: 'VNC', mode: 'plaintext', severity: 'critical', why: 'VNC sends the session and password in clear text.' },
  5985: { service: 'WinRM', mode: 'plaintext', severity: 'high', why: 'WinRM over HTTP exposes admin credentials.' },
  5986: { service: 'WinRM TLS', mode: 'encrypted', severity: null, why: 'TLS-protected remote management.' },
  6379: { service: 'Redis', mode: 'plaintext', severity: 'high', why: 'Redis has no transport encryption by default.' },
  6443: { service: 'Kubernetes API', mode: 'encrypted', severity: null, why: 'TLS-protected control plane.' },
  8000: { service: 'HTTP alt', mode: 'plaintext', severity: 'high', why: 'Plain HTTP on an alternate port.' },
  8080: { service: 'HTTP alt', mode: 'plaintext', severity: 'high', why: 'Plain HTTP on an alternate port.' },
  8081: { service: 'HTTP alt', mode: 'plaintext', severity: 'high', why: 'Plain HTTP on an alternate port.' },
  8443: { service: 'HTTPS alt', mode: 'encrypted', severity: null, why: 'TLS-protected transport.' },
  8883: { service: 'MQTTS', mode: 'encrypted', severity: null, why: 'TLS-protected MQTT.' },
  9092: { service: 'Kafka', mode: 'plaintext', severity: 'medium', why: 'Kafka traffic is unencrypted without TLS listeners.' },
  9200: { service: 'Elasticsearch', mode: 'plaintext', severity: 'high', why: 'Elasticsearch HTTP API is unauthenticated and unencrypted by default.' },
  9300: { service: 'ES transport', mode: 'plaintext', severity: 'high', why: 'Elasticsearch node transport is unencrypted.' },
  9418: { service: 'git', mode: 'plaintext', severity: 'medium', why: 'The git:// protocol has no encryption or authentication.' },
  11211: { service: 'Memcached', mode: 'plaintext', severity: 'high', why: 'Memcached has no transport encryption.' },
  27017: { service: 'MongoDB', mode: 'plaintext', severity: 'high', why: 'MongoDB is unencrypted unless TLS is configured.' },
  51820: { service: 'WireGuard', mode: 'encrypted', severity: null, why: 'VPN tunnel.' }
};

function classify(port, proto) {
  const entry = PORTS[port];
  if (entry) {
    const override = proto === 'udp' ? entry.udp : proto === 'tcp' ? entry.tcp : null;
    const chosen = override || entry;
    return {
      service: chosen.service,
      mode: chosen.mode,
      severity: chosen.mode === 'plaintext' ? chosen.severity || 'medium' : null,
      why: chosen.why,
      known: true
    };
  }
  if (!port) {
    return { service: '—', mode: 'unknown', severity: null, why: 'No remote port recorded.', known: false };
  }
  return {
    service: port < 1024 ? 'unrecognized system port' : 'unrecognized port',
    mode: 'unknown',
    severity: null,
    why: 'Port is not in the protocol knowledge base, so encryption cannot be confirmed.',
    known: false
  };
}

function isLoopback(host) {
  if (!host) return false;
  return host === '::1' || host === '::' || host === '0.0.0.0' || host === '*' || host.startsWith('127.');
}

function isLinkLocal(host) {
  return !!host && (host.startsWith('169.254.') || host.toLowerCase().startsWith('fe80:'));
}

function isPrivateIp(host) {
  if (!host || host === '*' || host === '0.0.0.0' || host === '::' || host === '::1') return true;
  if (host.startsWith('127.') || host.startsWith('10.') || host.startsWith('192.168.') || host.startsWith('169.254.')) return true;
  if (host.startsWith('172.')) {
    const second = Number(host.split('.')[1]);
    if (second >= 16 && second <= 31) return true;
  }
  const lower = host.toLowerCase();
  if (lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80:')) return true;
  return false;
}

module.exports = { classify, isLoopback, isPrivateIp, isLinkLocal, SEVERITY_RANK, PORTS };
