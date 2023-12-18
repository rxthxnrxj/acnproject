from scapy.all import sniff, wrpcap

# Define a callback function to handle captured packets
def packet_handler(packet):
    # Process or analyze the packet as needed
    print(packet)

    # Append the packet to a list (for later saving to a pcap file)
    captured_packets.append(packet)
    # Save the captured packets to a pcap file
    # wrpcap('captured_packets.pcap', packet, append=True)
# Initialize an empty list to store captured packets
captured_packets = []

# Sniff packets on the default network interface (you may need to run this as root)
sniff(prn=packet_handler, store=0, count=100)  # Capture 10 packets for demonstration


wrpcap('captured_packets.pcap', captured_packets)
print(captured_packets[0])
