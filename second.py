from scapy.all import rdpcap, IP, TCP

def analyze_pcap(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Initialize variables for Congestion Window Tracking
    cwnd_values = []

    # Initialize variables for packet tracking
    last_seq = None
    retransmissions = 0
    out_of_order = 0
    packet_loss = 0

    # Iterate through packets
    for index, packet in enumerate(packets):
        if IP in packet and TCP in packet:
            # Extract TCP header information
            seq_num = packet[TCP].seq
            window_size = packet[TCP].window

            # Update Congestion Window Tracking
            cwnd_values.append(window_size)

            # Detect retransmissions
            if last_seq is not None and seq_num < last_seq:
                retransmissions += 1
                print(f"Retransmission detected at packet {index}")
                

            # Detect out-of-order packets
            if last_seq is not None and seq_num != last_seq + 1:
                out_of_order += 1
                print(f"Out-of-order packet detected at packet {index}")

            # Check for packet loss
            if packet_loss == 0 and last_seq is not None and seq_num > last_seq + 1:
                packet_loss += 1
                print(f"Packet loss detected at packet {index}")

            print(packets[index].summary())
            # Update last sequence number
            last_seq = seq_num

    # Print summary
    print("\nAnalysis Summary:")
    print(f"Retransmissions: {retransmissions}")
    print(f"Out-of-Order Packets: {out_of_order}")
    print(f"Packet Loss: {packet_loss}")

    return cwnd_values

if __name__ == "__main__":
    # Replace 'your_pcap_file.pcap' with the path to the user-provided pcap file
    pcap_file_path = 'captured_packets.pcap'

    # Analyze the pcap file
    congestion_window_data = analyze_pcap(pcap_file_path)
    print(congestion_window_data,len(congestion_window_data))
    

    # You can use the 'congestion_window_data' for further analysis or visualization
