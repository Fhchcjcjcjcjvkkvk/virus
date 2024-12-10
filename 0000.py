import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile
from scapy.all import sniff, Dot11, Dot11Beacon

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
    iface = wifi.interfaces()[0]  # Assuming the first interface
    iface.scan()
    time.sleep(2)  # Wait for scan results to populate
    networks = iface.scan_results()
    return networks

# Function to sniff for beacon frames and extract channel information
def get_channel_from_sniffed_data(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11].info.decode(errors="ignore")
        channel = ord(packet[Dot11Elt:3].info)  # Extracting the channel from the Beacon frame
        return ssid, channel
    return None, None

# Function to continuously sniff and update channel information
def sniff_for_channels():
    network_channels = {}
    def handle_packet(packet):
        ssid, channel = get_channel_from_sniffed_data(packet)
        if ssid and channel:
            network_channels[ssid] = channel

    # Start sniffing in the background (for 30 seconds)
    sniff(prn=handle_packet, store=0, timeout=30)  # Timeout after 30 seconds
    return network_channels

# Function to display the network details with channel info
def live_scan():
    # Get channel information from sniffed data
    network_channels = sniff_for_channels()

    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30} {'Channel':<10}")
        print("-" * 100)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address) directly
            essid = network.ssid   # Access the ESSID (network name) directly
            signal = network.signal  # Access the signal strength directly

            # Get the authentication type using netsh for each ESSID
            auth = get_authentication(essid)

            # Get the channel from sniffed data
            channel = network_channels.get(essid, "Unknown")

            # Display the information
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} {channel:<10}")

        time.sleep(5)  # Wait for 5 seconds before the next scan

if __name__ == "__main__":
    live_scan()  # Start the live scan
