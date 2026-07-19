from collections import Counter
from config import PING_FLOOD_THRESHOLD, PORT_SCAN_THRESHOLD


def security_analysis(packet_records):

    icmp_counter = Counter()
    tcp_ports = {}

    for packet in packet_records:

        src = packet["src_ip"]

        if packet["transport_protocol"] == "ICMP":
            icmp_counter[src] += 1

        if packet["transport_protocol"] == "TCP":

            if src not in tcp_ports:
                tcp_ports[src] = set()

            tcp_ports[src].add(packet["dst_port"])

    print("\nSecurity Analysis")

    # ---------------------------
    # ICMP Flood Detection
    # ---------------------------

    flood = False

    for ip, count in icmp_counter.items():

        if count >= PING_FLOOD_THRESHOLD:

            print(f"ICMP Flood Detected : {ip}")

            flood = True

    if not flood:
        print("ICMP Flood           : Not Detected")

    # ---------------------------
    # Port Scan Detection
    # ---------------------------

    scan = False

    for ip, ports in tcp_ports.items():

        if len(ports) >= PORT_SCAN_THRESHOLD:

            print(f"Possible Port Scan   : {ip}")

            scan = True

    if not scan:
        print("Port Scan            : Not Detected")