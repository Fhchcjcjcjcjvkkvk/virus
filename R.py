from scapy.all import *
import re

# Function to handle each packet
def handle_packet(packet):
    # Check if the packet is a Beacon Frame (IEEE 802.11 management frame type)
    if packet.haslayer(Dot11Beacon):
        # Extract BSSID (MAC address of the AP)
        bssid = packet[Dot11].addr3

        # Extract the "Information Elements" which contain the Authentication Type
        info_elements = packet[Dot11Beacon].info
        auth_protocol = None

        # Check if we can extract the Authentication protocol
        if b"RSN" in info_elements:
            auth_protocol = "WPA/WPA2 (RSN)"
        elif b"WPA" in info_elements:
            auth_protocol = "WPA"
        elif b"Open" in info_elements:
            auth_protocol = "Open"
        else:
            auth_protocol = "Unknown"

        # Print the BSSID and Authentication Protocol
        print(f"BSSID: {bssid}, Authentication: {auth_protocol}")

# Main function to read packets from a pcap file
def analyze_pcap(file_path):
    print(f"Analyzing pcap file: {file_path}...")
    packets = rdpcap(file_path)  # Read packets from pcap file
    for packet in packets:
        handle_packet(packet)

# Run the analysis with the path to the .pcap file
if __name__ == "__main__":
    pcap_file = "capture.pcap"  # Replace with your capture file
    analyze_pcap(pcap_file)
