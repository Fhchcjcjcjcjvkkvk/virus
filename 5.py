from scapy.all import *
import logging

# Disable Scapy's warning message
logging.basicConfig(level=logging.ERROR)

# Function to handle the sniffed packet and extract Wi-Fi network details
def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        # Check if the packet is a Beacon frame
        if pkt.type == 0 and pkt.subtype == 8:
            # Extract BSSID, ESSID, and Signal Strength (RSSI)
            bssid = pkt.addr3
            essid = pkt.info.decode('utf-8', errors='ignore')
            signal_strength = pkt.dBm_AntSignal
            interface = conf.iface

            print(f"Interface: {interface}")
            print(f"BSSID: {bssid}")
            print(f"ESSID: {essid}")
            print(f"Signal Strength (RSSI): {signal_strength} dBm")
            print("-" * 40)

# Function to start the Wi-Fi scan
def scan_wifi(interface="WiFi"):
    print(f"Starting Wi-Fi scan on interface {interface}...\n")
    # Set the interface to monitor mode (if necessary)
    conf.iface = interface
    
    # Sniffing for 30 seconds and looking for Beacon frames
    sniff(prn=packet_handler, timeout=30, iface=interface, store=0)

# Start the scan on the desired interface (e.g., "wlan0")
scan_wifi("WiFi")  # You can replace "WiFi" with your actual interface name
