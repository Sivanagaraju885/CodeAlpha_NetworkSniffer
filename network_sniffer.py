from scapy.all import *

packet_count = 0

def process_packet(packet):
    global packet_count
    packet_count += 1

    if packet.haslayer(IP):
        print(f"\nPacket #{packet_count}")
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        print(f"Packet Size    : {len(packet)} bytes")

sniff(count=20, prn=process_packet, store=False)