# TrafficAnalysis.py

from collections import defaultdict
from scapy.all import sniff, IP, TCP, ICMP
import time
import socket

class TrafficAnalyzer:
    def __init__(self, iface=None):
        """
        iface: network interface to sniff on (e.g. 'Wi-Fi', 'eth0', etc.)
        """
        self.iface       = iface
        self.my_ip       = self._get_local_ip()
        self.connections = defaultdict(list)

    def _get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
        finally:
            s.close()

    def _get_service(self, port):
        # quick common lookup; fallback to unknown
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 514: "syslog", 6667: "irc", 102: "warezmaster"
        }
        return services.get(port, "unknown")

    def start(self, packet_callback):
        sniff(iface=self.iface,
              prn=lambda pkt: packet_callback(self.analyze_packet(pkt)),
              store=False)

    def analyze_packet(self, packet):
        if not packet.haslayer(IP):
            return None

        ip    = packet[IP]
        # only inbound to this host
        if ip.dst != self.my_ip:
            return None

        ts    = time.time()
        proto = ip.proto
        sport = packet[TCP].sport if packet.haslayer(TCP) else 0
        dport = packet[TCP].dport if packet.haslayer(TCP) else 0

        # group by dst port & proto, ignoring sport so floods aggregate
        flow = (ip.src, ip.dst, dport, proto)
        self.connections[flow].append((ts, len(packet)))

        # only last 10 seconds
        recent = [(t, sz) for t, sz in self.connections[flow] if ts - t <= 10]
        self.connections[flow] = recent

        count       = len(recent)
        total_bytes = sum(sz for _, sz in recent)

        if count > 1:
            duration = recent[-1][0] - recent[0][0]
            if duration <= 0:
                duration = 0.001
        else:
            duration = 0.001

        # determine service name
        service = self._get_service(dport) if packet.haslayer(TCP) else "unknown"

        return {
            "packet_size":      len(packet),
            "packet_rate":      count / duration,
            "byte_rate":        total_bytes / duration,
            "tcp_flags":        int(packet[TCP].flags) if packet.haslayer(TCP) else 0,
            "fragmented":       bool(getattr(ip, "frag", 0) > 0),
            "fragment_offset":  getattr(ip, "frag", 0),
            "protocol":         proto,
            "ttl":              ip.ttl,
            "source_ip":        ip.src,
            "destination_ip":   ip.dst,
            "source_port":      sport,
            "destination_port": dport,
            "service":          service
        }
