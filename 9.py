import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile

# Function to get authentication details and channel from netsh using ESSID
def get_authentication_and_channel(essid):
    # Run netsh to get the available network's authentication and channel information
    command = 'netsh wlan show networks mode=bssid'
    result = os.popen(command).read()

    # Parse the output to find the "Authentication" and "Channel" lines for the specific ESSID
    lines = result.split("\n")
    current_ssid = None
    authentication = "Unknown"
    channel = "Unknown"

    for line in lines:
        line = line.strip()

        if line.startswith("SSID ") and essid in line:  # Match the ESSID
            current_ssid = essid
        elif "Authentication" in line and current_ssid == essid:
            # Extract the authentication type (e.g., WPA2, WPA3)
            authentication = line.split(":")[1].strip()
        elif "Channel" in line and current_ssid == essid:
            # Extract the channel number
            channel = line.split(":")[1].strip()

    return authentication, channel  # Return both authentication and channel


# Function to scan WiFi networks
def scan_wifi():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Assuming the first interface
    iface.scan()
    time.sleep(2)  # Wait for scan results to populate
    networks = iface.scan_results()
    return networks


# Function to display the network details
def live_scan():
    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30} {'Channel':<10}")
        print("-" * 100)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address) directly
            essid = network.ssid   # Access the ESSID (network name) directly
            signal = network.signal  # Access the signal strength directly

            # Get the authentication type and channel using netsh for each ESSID
            auth, channel = get_authentication_and_channel(essid)

            # Display the information
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} {channel:<10}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    live_scan()  # Start the live scan
