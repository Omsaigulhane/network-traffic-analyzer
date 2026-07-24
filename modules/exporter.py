from collections import Counter, defaultdict
import pandas as pd


def layer_statistics(packet_records, field_name, title):
   
    values = [packet[field_name] for packet in packet_records]
    counts = Counter(values)

    print(f"\n{title}")

    for protocol, count in counts.items():
        print(f"{protocol}: {count}")


def top_packet_senders(packet_records):
    
    counter = Counter()

    for packet in packet_records:
        if packet["src_ip"] != "N/A":
            counter[packet["src_ip"]] += 1

    print("\nTop Packet Senders")

    for ip, count in counter.most_common(5):
        print(f"{ip}: {count} packets")


def top_bandwidth_senders(packet_records):
   
    bandwidth = defaultdict(int)

    for packet in packet_records:
        if packet["src_ip"] != "N/A":
            bandwidth[packet["src_ip"]] += packet["size"]

    print("\nTop Bandwidth Senders")

    top_hosts = sorted(
        bandwidth.items(),
        key=lambda item: item[1],
        reverse=True
    )[:5]

    for ip, total_bytes in top_hosts:
        print(f"{ip}: {total_bytes} bytes")


def packet_size_statistics(packet_records):
    
    sizes = [packet["size"] for packet in packet_records]

    if not sizes:
        return

    print("\nPacket Size Statistics")

    print(f"Average Packet Size : {sum(sizes) / len(sizes):.2f} bytes")
    print(f"Maximum Packet Size : {max(sizes)} bytes")
    print(f"Minimum Packet Size : {min(sizes)} bytes")


def bandwidth_estimation(packet_records, capture_time):
   
    total_bytes = sum(packet["size"] for packet in packet_records)

    if capture_time <= 0:
        return

    bandwidth_bps = (total_bytes * 8) / capture_time
    bandwidth_mbps = bandwidth_bps / 1_000_000

    print("\nBandwidth Estimation")

    print(f"Capture Duration : {capture_time:.2f} seconds")
    print(f"Total Data       : {total_bytes} bytes")
    print(f"Bandwidth        : {bandwidth_mbps:.3f} Mbps")


def export_csv(packet_records, output_path="exports/network_traffic.csv"):
   
    df = pd.DataFrame(packet_records)
    df.to_csv(output_path, index=False)

    print("\nCSV exported successfully.")
