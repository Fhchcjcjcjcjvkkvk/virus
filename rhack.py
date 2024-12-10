import os
import time
import pywifi
from pywifi import PyWiFi

# Function to get authentication details using netsh
def get_authentication_details():
    # Run netsh to get details of all Wi-Fi networks
    command = 'netsh wlan show networks mode=bssid'
    result = os.popen(command).read()

    # Parse the output and build a dictionary mapping ESSIDs to their authentication types
    auth_details = {}
    current_ssid = None

    for line in result.split("\n"):
        line = line.strip()

        if line.startswith("SSID "):  # Found an SSID
            current_ssid = line.split(" : ")[1].strip()
        elif "Authentication" in line and current_ssid:
            auth_type = line.split(" : ")[1].strip()
            auth_details[current_ssid] = auth_type

    return auth_details


# Function to scan Wi-Fi networks using pywifi
def scan_wifi():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Assuming the first interface
    iface.scan()
    time.sleep(2)  # Wait for scan results to populate
    networks = iface.scan_results()
    return networks


# Function to display live Wi-Fi network details
def live_scan():
    while True:
        networks = scan_wifi()  # Perform the Wi-Fi scan
        auth_details = get_authentication_details()  # Fetch authentication types using netsh

        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live updates
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30}")
        print("-" * 90)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address) directly
            essid = network.ssid  # Access the ESSID (network name) directly
            signal = network.signal  # Access the signal strength directly
            
            # Get authentication type from the auth_details dictionary
            auth = auth_details.get(essid, "Unknown")

            # Display the information
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    live_scan()  # Start the live scan
