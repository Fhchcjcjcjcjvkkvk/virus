import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile
from scapy.all import sniff, Dot11Beacon
from collections import defaultdict

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
    iface = wifi.interfaces()[0]  # Assuming the first interface
    iface.scan()
    time.sleep(2)  # Wait for scan results to populate
    networks = iface.scan_results()
    return networks


# Dictionary to hold beacon counts
beacon_counts = defaultdict(int)


# Function to count beacon frames using scapy
def count_beacons(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2  # Get the BSSID (MAC address) of the AP
        beacon_counts[bssid] += 1  # Increment beacon count for that BSSID


# Function to display the network details
def live_scan():
    # Start sniffing in the background for beacon frames
    sniff(prn=count_beacons, iface="wlan0", store=0, count=0, timeout=10)  # Adjust 'iface' if needed
    
    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30} {'Beacons':<10}")
        print("-" * 110)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address) directly
            essid = network.ssid   # Access the ESSID (network name) directly
            signal = network.signal  # Access the signal strength directly

            # Get the authentication type using netsh for each ESSID
            auth = get_authentication(essid)

            # Get the beacon count from the dictionary
            beacon_count = beacon_counts.get(bssid, 0)

            # Display the information
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} {beacon_count:<10}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    live_scan()  # Start the live scan
