import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile
import pyshark
from collections import defaultdict, deque
import threading

# Global dictionaries to track:
# 1. Packet reception count (successful packets for RXQ calculation)
# 2. Total packets in the last 10 seconds for RXQ calculation
received_packets = defaultdict(int)
packet_timestamps = defaultdict(deque)  # Track timestamps for packet arrivals

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
    time.sleep(2)  # Wait for scan results to populate
    networks = iface.scan_results()
    return networks


# Function to capture packets (ARP, IP, ICMP, or any IP-based packet) using pyshark
def packet_handler(pkt):
    current_time = time.time()

    # If the packet is ARP, IP, ICMP, or UDP, we consider it as successfully received
    if 'ARP' in pkt:
        received_packets['ARP'] += 1
    elif 'IP' in pkt:
        received_packets['IP'] += 1
    elif 'ICMP' in pkt:
        received_packets['ICMP'] += 1
    elif 'UDP' in pkt:
        received_packets['UDP'] += 1

    # Keep track of the timestamp of the current packet
    packet_timestamps['All'].append(current_time)
    
    # Cleanup old packets (older than 10 seconds) for RXQ calculation
    for key in packet_timestamps:
        while packet_timestamps[key] and current_time - packet_timestamps[key][0] > 10:
            packet_timestamps[key].popleft()


# Function to start sniffing packets using pyshark (in normal mode)
def start_sniffing():
    cap = pyshark.LiveCapture(interface="WiFi", only_syntax=True)  # Replace 'Wi-Fi' with your network interface name
    for pkt in cap.sniff_continuously(packet_count=1000):  # Capture packets continuously
        packet_handler(pkt)  # Process the packet


# Function to calculate RXQ (receive quality) as a percentage of successfully received packets
def calculate_rxq():
    total = sum(received_packets.values())
    total_time = time.time()

    # Count total number of received packets in the last 10 seconds
    # Cleanup old packets (older than 10 seconds)
    for key in received_packets:
        while packet_timestamps[key] and total_time - packet_timestamps[key][0] > 10:
            packet_timestamps[key].popleft()

    # Calculate RXQ as the percentage of successfully received packets
    if total > 0:
        rxq_percentage = (total / len(packet_timestamps['All'])) * 100
        return round(rxq_percentage, 2)
    return 0


# Function to display the network details along with RXQ and packet counts
def live_scan():
    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30} {'RXQ %':<15}")
        print("-" * 100)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address)
            essid = network.ssid   # Access the ESSID (network name)
            signal = network.signal  # Access the signal strength

            # Get the authentication type using netsh for each ESSID
            auth = get_authentication(essid)

            # Calculate the RXQ for the network
            rxq = calculate_rxq()

            # Display the network information along with RXQ
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} {rxq:<15}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    # Start sniffing for packets in a separate thread using pyshark
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    live_scan()  # Start the live scan
