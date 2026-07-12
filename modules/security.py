from collections import Counter
from config import PING_FLOOD_THRESHOLD, PORT_SCAN_THRESHOLD


def security_analysis(packet_records):
    """
    Detect simple network anomalies.
    """

    icmp_counter = Counter()
    port_counter = Counter()

    for packet in packet_records:

        if packet["protocol"] == "ICMP":
            icmp_counter[packet["src_ip"]] += 1

        if packet["protocol"] == "TCP":
            port_counter[packet["src_ip"]].add(packet["dst_port"])


def security_analysis(packet_records):
    """
    Detect simple Ping Flood and Port Scan activity.
    """

    icmp_counter = Counter()
    port_counter = {}

    for packet in packet_records:

        src = packet["src_ip"]

        if packet["protocol"] == "ICMP":
            icmp_counter[src] += 1

        if packet["protocol"] == "TCP":

            if src not in port_counter:
                port_counter[src] = set()

            port_counter[src].add(packet["dst_port"])

    print("\nSecurity Analysis")

    ping_detected = False

    for ip, count in icmp_counter.items():

        if count >= PING_FLOOD_THRESHOLD:

            print(f"Ping Flood Detected : {ip}")
            ping_detected = True

    if not ping_detected:
        print("Ping Flood          : Not Detected")

    scan_detected = False

    for ip, ports in port_counter.items():

        if len(ports) >= PORT_SCAN_THRESHOLD:

            print(f"Possible Port Scan  : {ip}")
            scan_detected = True

    if not scan_detected:
        print("Port Scan           : Not Detected")