import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile
from scapy.all import sniff, ARP, IP, UDP, ICMP, Ether
from collections import defaultdict
import threading

# Global dictionary to track the number of captured packets
data_packets_count = defaultdict(int)

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


# Function to capture packets (ARP, ICMP, or any IP-based packet) on the network
def packet_handler(pkt):
    # If the packet is an IP packet (ARP, ICMP, etc.)
    if pkt.haslayer(ARP):
        data_packets_count['ARP'] += 1
    elif pkt.haslayer(IP):
        data_packets_count['IP'] += 1
    elif pkt.haslayer(ICMP):
        data_packets_count['ICMP'] += 1
    elif pkt.haslayer(UDP):
        data_packets_count['UDP'] += 1

# Function to start sniffing packets on the interface (non-monitor mode)
def start_sniffing():
    # Sniff ARP, IP, ICMP, and UDP packets using scapy in non-monitor mode
    sniff(prn=packet_handler, store=0, iface="WiFi", timeout=60)  # Adjust interface name if necessary

# Function to display the network details along with captured packet counts
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

            # Get the total packet count (ARP, IP, ICMP, UDP)
            arp_count = data_packets_count.get('ARP', 0)
            ip_count = data_packets_count.get('IP', 0)
            icmp_count = data_packets_count.get('ICMP', 0)
            udp_count = data_packets_count.get('UDP', 0)

            # Display the network information along with captured packet counts
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} "
                  f"ARP: {arp_count} IP: {ip_count} ICMP: {icmp_count} UDP: {udp_count}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    # Start sniffing for packets in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    live_scan()  # Start the live scan
