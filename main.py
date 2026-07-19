from config import PACKET_LIMIT
from modules.capture import capture_packets
from modules.analyzer import analyze_packet
from modules.exporter import (
    export_csv,
    layer_statistics,
    top_packet_senders,
    top_bandwidth_senders,
    packet_size_statistics,
    bandwidth_estimation,
)
from modules.visualizer import protocol_chart
from modules.security import security_analysis


def main():

    print(f"Capturing {PACKET_LIMIT} packets...\n")

    packets, capture_time = capture_packets(PACKET_LIMIT)

    packet_records = []

    # ==========================
    # Packet Analysis
    # ==========================

    for packet in packets:

        result = analyze_packet(packet)

        packet_records.append(result)

        print(
            f"Network: {result['network_protocol']} | "
            f"Transport: {result['transport_protocol']} | "
            f"Application: {result['application_protocol']} | "
            f"Source IP: {result['src_ip']} | "
            f"Destination IP: {result['dst_ip']} | "
            f"Source Port: {result['src_port']} | "
            f"Destination Port: {result['dst_port']} | "
            f"Size: {result['size']} bytes | "
            f"Domain: {result['domain']}"
        )

    # ==========================
    # Analysis Report
    # ==========================

    print("\n" + "=" * 60)
    print("NETWORK TRAFFIC ANALYSIS REPORT")
    print("=" * 60)

    print(f"\nTotal Packets Captured : {len(packet_records)}")

    layer_statistics(
        packet_records,
        "network_protocol",
        "Network Layer Statistics",
    )

    layer_statistics(
        packet_records,
        "transport_protocol",
        "Transport Layer Statistics",
    )

    layer_statistics(
        packet_records,
        "application_protocol",
        "Application Layer Statistics",
    )

    top_packet_senders(packet_records)
    top_bandwidth_senders(packet_records)

    packet_size_statistics(packet_records)

    bandwidth_estimation(packet_records, capture_time)

    export_csv(packet_records)

    # ==========================
    # Charts
    # ==========================

    protocol_chart(
        packet_records,
        "network_protocol",
        "Network Layer Distribution",
        "charts/network_distribution.png",
    )

    protocol_chart(
        packet_records,
        "transport_protocol",
        "Transport Layer Distribution",
        "charts/transport_distribution.png",
    )

    protocol_chart(
        packet_records,
        "application_protocol",
        "Application Layer Distribution",
        "charts/application_distribution.png",
    )

    # ==========================
    # Security Analysis
    # ==========================

    security_analysis(packet_records)


if __name__ == "__main__":
    main()