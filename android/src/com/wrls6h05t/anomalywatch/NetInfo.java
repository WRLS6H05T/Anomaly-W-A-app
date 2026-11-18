package com.wrls6h05t.anomalywatch;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/** A fingerprint of the network the device is currently attached to. */
final class NetInfo {

    String transport = "offline";
    String iface = "";
    String ssid = "";
    String gateway = "";
    String dns = "";
    String privateDns = "off";
    boolean vpn;
    boolean metered;
    String fingerprint = "";

    static NetInfo snapshot(Context ctx) {
        NetInfo info = new NetInfo();
        try {
            ConnectivityManager cm =
                    (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return info;

            Network active = cm.getActiveNetwork();
            NetworkCapabilities caps = active == null ? null : cm.getNetworkCapabilities(active);
            LinkProperties lp = active == null ? null : cm.getLinkProperties(active);

            if (caps != null) {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) info.transport = "Wi-Fi";
                else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) info.transport = "Cellular";
                else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) info.transport = "Ethernet";
                else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) info.transport = "Bluetooth";
                else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) info.transport = "VPN";
                else info.transport = "Other";
                info.metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
            }

            for (Network n : cm.getAllNetworks()) {
                NetworkCapabilities c = cm.getNetworkCapabilities(n);
                if (c != null && c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    info.vpn = true;
                    break;
                }
            }

            if (lp != null) {
                info.iface = lp.getInterfaceName() == null ? "" : lp.getInterfaceName();
                List<RouteInfo> routes = lp.getRoutes();
                if (routes != null) {
                    for (RouteInfo r : routes) {
                        if (r.isDefaultRoute() && r.getGateway() != null) {
                            info.gateway = r.getGateway().getHostAddress();
                            break;
                        }
                    }
                }
                List<InetAddress> servers = lp.getDnsServers();
                if (servers != null && !servers.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (InetAddress a : servers) {
                        if (sb.length() > 0) sb.append(", ");
                        sb.append(a.getHostAddress());
                    }
                    info.dns = sb.toString();
                }
                if (Build.VERSION.SDK_INT >= 28) {
                    boolean active2 = lp.isPrivateDnsActive();
                    String name = lp.getPrivateDnsServerName();
                    if (active2) info.privateDns = name == null || name.isEmpty() ? "on" : name;
                }
            }

            if ("Wi-Fi".equals(info.transport)) {
                try {
                    WifiManager wm = (WifiManager) ctx.getApplicationContext()
                            .getSystemService(Context.WIFI_SERVICE);
                    WifiInfo wi = wm == null ? null : wm.getConnectionInfo();
                    if (wi != null) {
                        String name = wi.getSSID();
                        if (name != null && !name.isEmpty()) {
                            if (name.startsWith("\"") && name.endsWith("\"") && name.length() > 1) {
                                name = name.substring(1, name.length() - 1);
                            }
                            if (!"<unknown ssid>".equals(name) && !"0x".equals(name)) info.ssid = name;
                        }
                    }
                } catch (Exception ignored) {
                    // SSID is hidden without a location permission on newer builds
                }
            }

            info.fingerprint = info.transport + "|" + (info.ssid.isEmpty() ? info.iface : info.ssid)
                    + "|" + info.gateway + "|" + info.dns;
        } catch (Exception ignored) {
            // leave defaults; the app still shows what it could read
        }
        return info;
    }

    String label() {
        if (ssid != null && !ssid.isEmpty()) return transport + " · " + ssid;
        if (iface != null && !iface.isEmpty()) return transport + " · " + iface;
        return transport;
    }

    String describe() {
        StringBuilder sb = new StringBuilder(label());
        if (gateway != null && !gateway.isEmpty()) sb.append(" (gateway ").append(gateway).append(')');
        if (vpn) sb.append(", via VPN");
        return sb.toString();
    }

    boolean hasDns() {
        return dns != null && !dns.isEmpty();
    }

    List<String> lines() {
        List<String> out = new ArrayList<>();
        out.add("Transport|" + transport + (metered ? " · metered" : ""));
        if (ssid != null && !ssid.isEmpty()) out.add("Wi-Fi network|" + ssid);
        if (iface != null && !iface.isEmpty()) out.add("Interface|" + iface);
        if (gateway != null && !gateway.isEmpty()) out.add("Gateway|" + gateway);
        out.add("DNS servers|" + (dns.isEmpty() ? "none reported" : dns));
        out.add("Private DNS|" + ("off".equals(privateDns) ? "off (lookups in clear text)" : privateDns));
        out.add("VPN|" + (vpn ? "active" : "not detected"));
        return out;
    }
}
