from collections import Counter

import matplotlib.pyplot as plt


def protocol_chart(packet_records, output_path="charts/protocol_distribution.png"):
    """Create a protocol distribution chart and save it to disk."""
    protocols = [packet["protocol"] for packet in packet_records]
    counts = Counter(protocols)

    plt.figure(figsize=(8, 8))
    plt.pie(counts.values(), labels=counts.keys(), autopct="%1.1f%%")
    plt.title("Protocol Distribution")
    plt.savefig(output_path)
    plt.show()                 # Display window
    plt.close()


    print("\nChart saved successfully.")
