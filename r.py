import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile
from scapy.all import sniff, Dot11Beacon
from collections import defaultdict
import threading

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


# Beacon count tracker (global dictionary)
beacon_count = defaultdict(int)


# Function to capture beacons using Scapy
def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        essid = pkt[Dot11].info.decode()  # Extract SSID (ESSID)
        beacon_count[essid] += 1  # Increment beacon count for the network


# Function to start sniffing for beacons (sniffing in a separate thread)
def start_sniffing():
    # Sniff in monitor mode (replace 'wlan0' with your interface name)
    sniff(prn=packet_handler, store=0, iface="wlan0", timeout=60)  # Adjust interface name and timeout


# Function to display the network details along with beacon count
def live_scan():
    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30} {'Beacons':<10}")
        print("-" * 100)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address) directly
            essid = network.ssid   # Access the ESSID (network name) directly
            signal = network.signal  # Access the signal strength directly

            # Get the authentication type using netsh for each ESSID
            auth = get_authentication(essid)

            # Get the beacon count from the dictionary
            beacon_count_for_essid = beacon_count.get(essid, 0)

            # Display the information
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} {beacon_count_for_essid:<10}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    # Start sniffing for beacons in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    live_scan()  # Start the live scan
