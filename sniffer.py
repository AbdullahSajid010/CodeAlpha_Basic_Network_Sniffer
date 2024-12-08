import socket
import struct

# Function to format MAC addresses
def format_mac(mac_bytes):
    return ':'.join(format(b, '02x') for b in mac_bytes).upper()

# Function to parse Ethernet frames
def parse_ethernet_frame(packet):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', packet[:14])
    return format_mac(dest_mac), format_mac(src_mac), socket.ntohs(proto), packet[14:]

# Initialize a raw socket
def start_sniffer():
    # Create a raw socket to capture packets
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, _ = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = parse_ethernet_frame(raw_data)
        print(f'\nEthernet Frame:\nDestination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

# Main function to start sniffing
if __name__ == "__main__":
    start_sniffer()

