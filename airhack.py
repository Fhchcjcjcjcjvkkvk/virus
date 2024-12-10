import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile

# Function to get authentication and BSSID details from netsh using ESSID
def get_authentication_and_bssid(essid):
    # Run netsh to get the available network's authentication and BSSID information
    command = 'netsh wlan show networks mode=bssid'
    result = os.popen(command).read()

    # Initialize variables for output
    bssids = []
    authentication = "Unknown"
    current_ssid = None

    for line in result.split("\n"):
        line = line.strip()

        if line.startswith("SSID ") and essid in line:  # Match the ESSID
            current_ssid = essid
        elif current_ssid == essid:
            if line.startswith("BSSID "):  # Extract BSSID
                bssid = line.split(":")[1].strip()
                bssids.append(bssid)
            elif "Authentication" in line:  # Extract Authentication type
                authentication = line.split(":")[1].strip()

    return {"bssids": bssids, "authentication": authentication}


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
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30}")
        print("-" * 90)

        for network in networks:
            essid = network.ssid   # Access the ESSID (network name) directly
            signal = network.signal  # Access the signal strength directly

            # Get the authentication type and BSSID(s) using netsh for each ESSID
            details = get_authentication_and_bssid(essid)
            bssids = details["bssids"]
            authentication = details["authentication"]

            # Display the information for each BSSID
            for bssid in bssids:
                print(f"{bssid:<20} {essid:<30} {signal:<10} {authentication:<30}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    live_scan()  # Start the live scan
