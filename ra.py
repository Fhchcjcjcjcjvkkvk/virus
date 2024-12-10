import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile
from scapy.all import *

# Function to get authentication details from netsh using ESSID
def get_authentication(essid):
    # Run netsh to get the available network's authentication information
    command = 'netsh wlan show networks mode=bssid'
    result = os.popen(command).read()

    # Parse the output to find the "Authentication" line for the specific ESSID
    lines = result.split("\n")
    current_ssid = None

    for line in lines:
        line = line.strip()

        if line.startswith("SSID ") and essid in line:  # Match the ESSID
            current_ssid = essid
        elif "Authentication" in line and current_ssid == essid:
            # Extract and return the authentication type (e.g., WPA2, WPA3)
            return line.split(":")[1].strip()

    return "Unknown"  # If not found, return Unknown


# Function to scan WiFi networks using Scapy to capture BSSID
def scan_wifi():
    networks = set()  # Using a set to avoid duplicates

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            # Capture only Beacon frames or Probe Response frames
            if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                bssid = pkt.addr3  # BSSID is in the addr3 field for Beacon frames
                essid = pkt.info.decode() if pkt.info else "Hidden"
                networks.add((bssid, essid))

    # Start sniffing for 10 seconds to capture networks
    sniff(prn=packet_handler, timeout=10)

    return networks


# Function to display the network details
def live_scan():
    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30}")
        print("-" * 90)

        for bssid, essid in networks:
            signal = "N/A"  # Signal strength is not captured in Scapy sniffing directly
            auth = get_authentication(essid)

            # Display the information
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    live_scan()  # Start the live scan
