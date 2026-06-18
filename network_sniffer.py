from scapy.all import *

packet_count = 0

def process_packet(packet):
    global packet_count
    packet_count += 1

    if packet.haslayer(IP):
        packet.show()
        print(f"\nPacket #{packet_count}")
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")
        else:
            print("Protocol       : Other")

        print(f"Packet Size    : {len(packet)} bytes")

        if packet.haslayer(Raw):
            payload = packet[Raw].load[:100]  # First 50 bytes
            print(f"Payload        : {payload}")
        else:
            print("Payload        : No Raw Payload")

sniff(count=100, prn=process_packet, store=False)  
