from scapy.all import sniff
import time
def capture_packets(packet_count=5):
   
    print(f"Capturing {packet_count} packets...")

    start_time = time.time()

    packets = sniff(count=packet_count)

    end_time = time.time()

    capture_time = end_time - start_time

    print(f"Successfully captured {len(packets)} packets.")

    return packets, capture_time