from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, IPv6

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    123: "NTP",
    443: "HTTPS",
}


def analyze_packet(packet):
   
    data = {
        "src_ip": "N/A",
        "dst_ip": "N/A",

        "network_protocol": "Unknown",
        "transport_protocol": "Unknown",
        "application_protocol": "Unknown",

        "src_port": "N/A",
        "dst_port": "N/A",

        "size": len(packet),

        "domain": "N/A",
    }

    
    if packet.haslayer(ARP):
        data["network_protocol"] = "ARP"
        data["src_ip"] = packet[ARP].psrc
        data["dst_ip"] = packet[ARP].pdst
        return data


    if packet.haslayer(IP):
        data["network_protocol"] = "IPv4"
        data["src_ip"] = packet[IP].src
        data["dst_ip"] = packet[IP].dst

    elif packet.haslayer(IPv6):
        data["network_protocol"] = "IPv6"
        data["src_ip"] = packet[IPv6].src
        data["dst_ip"] = packet[IPv6].dst

    else:
        return data

 
    if packet.haslayer(TCP):
        data["transport_protocol"] = "TCP"
        data["src_port"] = packet[TCP].sport
        data["dst_port"] = packet[TCP].dport

    elif packet.haslayer(UDP):
        data["transport_protocol"] = "UDP"
        data["src_port"] = packet[UDP].sport
        data["dst_port"] = packet[UDP].dport

    elif packet.haslayer(ICMP):
        data["transport_protocol"] = "ICMP"

     if packet.haslayer(DNS):

        data["application_protocol"] = "DNS"

        if packet.haslayer(DNSQR):
            try:
                data["domain"] = packet[DNSQR].qname.decode().rstrip(".")
            except Exception:
                pass

    else:

        ports = []

        if isinstance(data["src_port"], int):
            ports.append(data["src_port"])

        if isinstance(data["dst_port"], int):
            ports.append(data["dst_port"])

        for port in ports:
            if port in COMMON_PORTS:
                data["application_protocol"] = COMMON_PORTS[port]
                break

    return data
