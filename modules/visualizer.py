from collections import Counter
import matplotlib.pyplot as plt


def protocol_chart(packet_records,
                   field_name,
                   title,
                   output_path):

    values = [packet[field_name] for packet in packet_records]

    counts = Counter(values)

    plt.figure(figsize=(8,8))

    plt.pie(
        counts.values(),
        labels=counts.keys(),
        autopct="%1.1f%%"
    )

    plt.title(title)

    plt.savefig(output_path)

    plt.show()

    plt.close()

    print(f"\n{title} saved successfully.")