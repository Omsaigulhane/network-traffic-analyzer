from config import PACKET_LIMIT
from modules.analyzer import analyze_packet
from modules.capture import capture_packets
from modules.security import security_analysis
from modules.exporter import (
    export_csv,
    packet_size_statistics,
    protocol_statistics,
    top_talkers,
)
from modules.visualizer import protocol_chart

from modules.exporter import (
    export_csv,
    packet_size_statistics,
    protocol_statistics,
    top_talkers,
    bandwidth_estimation,
)


def main():
    print(f"Capturing {PACKET_LIMIT} packets...\n")

    packets, capture_time = capture_packets(PACKET_LIMIT)
    packet_records = []

    for packet in packets:
        result = analyze_packet(packet)
        packet_records.append(result)

        print(
            f"IP Version: {result['ip_version']} | "
            f"Source IP: {result['src_ip']} | "
            f"Destination IP: {result['dst_ip']} | "
            f"Protocol: {result['protocol']} | "
            f"Source Port: {result['src_port']} | "
            f"Destination Port: {result['dst_port']} | "
            f"Size: {result['size']} bytes | "
            f"Domain: {result['domain']}"
        )

    print("\n" + "=" * 50)
    print("NETWORK TRAFFIC ANALYSIS REPORT")
    print("=" * 50)
    print(f"\nTotal Packets Captured: {len(packet_records)}")

    protocol_statistics(packet_records)
    top_talkers(packet_records)
    packet_size_statistics(packet_records)
    export_csv(packet_records)
    protocol_chart(packet_records)
    bandwidth_estimation(packet_records, capture_time)
    security_analysis(packet_records)


if __name__ == "__main__":
    main()
    