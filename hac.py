import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile
import pyshark
from collections import defaultdict
import threading

# Global dictionary to track beacon frame counts
beacon_counts = defaultdict(int)

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


# Function to scan WiFi networks using pywifi
def scan_wifi():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Get the first interface
    iface.scan()
    
    # Wait for a while to allow scan results to populate
    # We don't rely on sleep; instead, we check if results are available
    networks = iface.scan_results()
    while not networks:  # If the results are empty, wait and try again
        time.sleep(1)
        networks = iface.scan_results()

    return networks


# Function to capture Beacon frames using pyshark
def packet_handler(pkt):
    # Check if the packet is a Beacon frame (management frame type)
    if 'beacon' in pkt:
        essid = pkt.wlan.ssid  # Extract ESSID from the Beacon frame
        beacon_counts[essid] += 1  # Increment the count for this ESSID

# Function to start sniffing packets using pyshark (in normal mode)
def start_sniffing():
    cap = pyshark.LiveCapture(interface="WiFi")  # Replace 'Wi-Fi' with your network interface name
    for pkt in cap.sniff_continuously(packet_count=1000):  # Capture packets continuously
        packet_handler(pkt)  # Process the packet


# Function to display the network details along with Beacon count
def live_scan():
    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30} {'Beacons':<10}")
        print("-" * 100)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address)
            essid = network.ssid   # Access the ESSID (network name)
            signal = network.signal  # Access the signal strength

            # Get the authentication type using netsh for each ESSID
            auth = get_authentication(essid)

            # Get the beacon count for the ESSID
            beacon_count = beacon_counts.get(essid, 0)

            # Display the network information along with the Beacon count
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} {beacon_count:<10}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    # Start sniffing for packets in a separate thread using pyshark
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    live_scan()  # Start the live scan
