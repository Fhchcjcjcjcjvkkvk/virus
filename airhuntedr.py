import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon
import time

# Function to handle and display information of the packets
def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):  # Only capture beacon frames (AP signals)
        # Extracting the required fields
        ssid = pkt[Dot11Beacon].info.decode(errors="ignore")
        bssid = pkt[Dot11].addr3
        signal_strength = pkt.dBm_AntSignal  # Signal strength (dBm)

        # Display the network information
        print(f"SSID: {ssid}, BSSID: {bssid}, Signal Strength: {signal_strength} dBm")

# Function to start sniffing
def sniff_networks():
    print("Scanning for available networks...")
    scapy.sniff(prn=packet_handler, iface="Wi-Fi", store=0)  # Change "wlan0" based on your network interface

# Start sniffing networks
sniff_networks()
