from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Packet processing function
def process_packet(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        # Determine the protocol
        if packet.haslayer(TCP):
            print(f"Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print(f"Protocol: ICMP")
        else:
            print(f"Protocol: Other")

        # Print payload data (if present)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
                print(f"Payload: {payload[:100]}")  # Print first 100 bytes of payload data
            else:
                print("No payload data")

        print("-" * 50)

def main():
    print("Starting packet sniffer...")
    # Start sniffing, calling process_packet for each captured packet
    sniff(filter="ip", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
