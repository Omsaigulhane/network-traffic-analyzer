from collections import Counter

import pandas as pd


def protocol_statistics(packet_records):
    """Print a simple protocol summary."""
    protocols = [packet["protocol"] for packet in packet_records]
    counts = Counter(protocols)

    print("\nProtocol Statistics")
    for protocol, count in counts.items():
        print(f"{protocol}: {count}")


def top_talkers(packet_records):
    """Print the most active source IPs."""
    counter = Counter()

    for packet in packet_records:
        if packet["src_ip"] != "N/A":
            counter[packet["src_ip"]] += 1

    print("\nTop Talkers")
    for ip, count in counter.most_common(5):
        print(f"{ip}: {count}")


def packet_size_statistics(packet_records):
    """Print min/avg/max packet sizes."""
    sizes = [packet["size"] for packet in packet_records]

    if not sizes:
        return

    print("\nPacket Size Statistics")
    print(f"Average Packet Size: {round(sum(sizes) / len(sizes), 2)} bytes")
    print(f"Maximum Packet Size: {max(sizes)} bytes")
    print(f"Minimum Packet Size: {min(sizes)} bytes")


def export_csv(packet_records, output_path="exports/network_traffic.csv"):
    """Export the packet data to a CSV file."""
    df = pd.DataFrame(packet_records)
    df.to_csv(output_path, index=False)
    print("\nCSV exported successfully.")

def bandwidth_estimation(packet_records, capture_time):
    """Estimate average bandwidth during packet capture."""

    total_bytes = sum(packet["size"] for packet in packet_records)

    if capture_time <= 0:
        return

    bandwidth_bps = (total_bytes * 8) / capture_time
    bandwidth_mbps = bandwidth_bps / 1_000_000

    print("\nBandwidth Estimation")
    print(f"Capture Duration      : {capture_time:.2f} seconds")
    print(f"Total Data Captured   : {total_bytes} bytes")
    print(f"Estimated Bandwidth   : {bandwidth_mbps:.3f} Mbps")