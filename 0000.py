import time
import os
import pywifi
import pyshark  # PyShark to capture network packets
from pywifi import PyWiFi, const, Profile

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

# Function to capture packets using PyShark and calculate packets per second
def get_packets_per_second(interface, capture_duration=10):
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=capture_duration)  # Capture for 10 seconds

    # Count the data packets captured
    packet_count = 0
    for packet in capture:
        if 'IP' in packet:  # Check if it's an IP packet (data packet)
            packet_count += 1

    # Calculate packets per second
    packets_per_second = packet_count / capture_duration
    return packets_per_second

# Function to scan WiFi networks
def scan_wifi():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Assuming the first interface
    iface.scan()
    time.sleep(2)  # Wait for scan results to populate
    networks = iface.scan_results()
    return networks

# Function to display the network details and packet count per second
def live_scan():
    interface = "WiFi"  # Replace with your actual network interface name
    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        
        # Get the packets per second over the last 10 seconds
        packets_per_second = get_packets_per_second(interface)

        # Display header and packet stats
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30} {'#/s':<15}")
        print("-" * 110)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address) directly
            essid = network.ssid   # Access the ESSID (network name) directly
            signal = network.signal  # Access the signal strength directly

            # Get the authentication type using netsh for each ESSID
            auth = get_authentication(essid)

            # Display the information
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} {packets_per_second:<15.2f}")

        time.sleep(5)  # Wait for 5 seconds before the next scan

if __name__ == "__main__":
    live_scan()  # Start the live scan
