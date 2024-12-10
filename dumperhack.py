import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile
from scapy.all import sniff, Dot11, Dot11Data, Dot11WEP
from collections import defaultdict
import threading

# Global dictionaries to track:
# 1. data_packets_count: Number of captured data packets for each BSSID
# 2. unique_iv_count: Set of unique IVs for WEP networks (to track IVs)
data_packets_count = defaultdict(int)
unique_iv_count = defaultdict(set)

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


# Function to scan WiFi networks
def scan_wifi():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Get the first interface
    iface.scan()
    time.sleep(2)  # Wait for scan results to populate
    networks = iface.scan_results()
    return networks


# Function to capture data packets and count IVs (for WEP)
def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        # If the packet is a data packet (Dot11Data), increment the counter
        if pkt.haslayer(Dot11Data):
            data_packets_count[pkt[Dot11].addr2] += 1  # Increment the data packet count for the source BSSID
            
            # If WEP is being used, track unique IVs (from Dot11WEP layer)
            if pkt.haslayer(Dot11WEP):
                iv = pkt[Dot11WEP].iv
                unique_iv_count[pkt[Dot11].addr2].add(iv)  # Add the IV to the set for unique count


# Function to start sniffing for packets (sniffing in a separate thread)
def start_sniffing():
    # Sniff for data packets in monitor mode on the 'Wi-Fi' interface
    sniff(prn=packet_handler, store=0, iface="Wi-Fi", timeout=60)  # Adjust interface name if necessary


# Function to display the network details along with data packets and IV count
def live_scan():
    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30} {'Data':<15}")
        print("-" * 100)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address)
            essid = network.ssid   # Access the ESSID (network name)
            signal = network.signal  # Access the signal strength

            # Get the authentication type using netsh for each ESSID
            auth = get_authentication(essid)

            # Get the number of data packets and unique IV count for WEP networks
            data_count = data_packets_count.get(bssid, 0)  # Get total data packets for BSSID
            unique_iv_count_for_bssid = len(unique_iv_count.get(bssid, set()))  # Count of unique IVs for WEP

            # If the network is WEP, show unique IVs, else show data packet count
            data_value = f"Data Packets: {data_count}, Unique IVs: {unique_iv_count_for_bssid}" if auth == "WEP" else f"Data Packets: {data_count}"

            # Display the network information along with data count and IV count (for WEP)
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} {data_value:<15}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    # Start sniffing for data packets in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    live_scan()  # Start the live scan
