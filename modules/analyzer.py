from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, IPv6


def analyze_packet(packet):
    """Extract a normalized summary from a captured packet."""
    data = {
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "protocol": "OTHER",
        "ip_version": "N/A",
        "src_port": "N/A",
        "dst_port": "N/A",
        "size": len(packet),
        "domain": "N/A",
    }

    if packet.haslayer(ARP):
        data["protocol"] = "ARP"
        data["src_ip"] = packet[ARP].psrc
        data["dst_ip"] = packet[ARP].pdst
        data["ip_version"] = "Layer2"
        return data

    if packet.haslayer(IPv6):
        data["ip_version"] = "IPv6"
        data["src_ip"] = packet[IPv6].src
        data["dst_ip"] = packet[IPv6].dst

        if packet.haslayer(TCP):
            data["protocol"] = "TCP"
            data["src_port"] = packet[TCP].sport
            data["dst_port"] = packet[TCP].dport
        elif packet.haslayer(UDP):
            data["protocol"] = "UDP"
            data["src_port"] = packet[UDP].sport
            data["dst_port"] = packet[UDP].dport

        return data

    if packet.haslayer(IP):
        data["ip_version"] = "IPv4"
        data["src_ip"] = packet[IP].src
        data["dst_ip"] = packet[IP].dst

        if packet.haslayer(TCP):
            data["protocol"] = "TCP"
            data["src_port"] = packet[TCP].sport
            data["dst_port"] = packet[TCP].dport
        elif packet.haslayer(UDP):
            data["protocol"] = "UDP"
            data["src_port"] = packet[UDP].sport
            data["dst_port"] = packet[UDP].dport

            if packet.haslayer(DNS):
                data["protocol"] = "DNS"
                try:
                    data["domain"] = packet[DNSQR].qname.decode()
                except Exception:
                    pass
        elif packet.haslayer(ICMP):
            data["protocol"] = "ICMP"

    return data
