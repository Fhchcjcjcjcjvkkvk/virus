import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile

# Function to get authentication details and BSSID from netsh using ESSID
def get_authentication_and_bssid(essid):
    # Run netsh to get the available network's authentication and BSSID information
    command = 'netsh wlan show networks mode=bssid'
    result = os.popen(command).read()

    # Parse the output to find the "Authentication" and "BSSID" lines for the specific ESSID
    lines = result.split("\n")
    current_ssid = None
    authentication = "Unknown"
    bssid = "Unknown"

    # Loop through the lines and extract relevant details for each network
    for line in lines:
        line = line.strip()

        if line.startswith("SSID "):  # A new network entry starts here
            # Extract the ESSID from the line and check if it matches
            current_ssid = line.split(":")[1].strip()  # Extract ESSID value

        if current_ssid == essid:
            if "Authentication" in line:
                # Extract the authentication type
                authentication = line.split(":")[1].strip()
            elif "BSSID" in line:
                # Extract the BSSID (MAC address)
                bssid = line.split(":")[1].strip()

    return authentication, bssid  # Return both authentication and BSSID


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
    network_details = {}  # Store network details (ESSID as key, auth and bssid as values)
    
    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30}")
        print("-" * 80)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address) directly
            essid = network.ssid   # Access the ESSID (network name) directly
            signal = network.signal  # Access the signal strength directly

            # Check if the ESSID is already in the dictionary, otherwise, get details from netsh
            if essid not in network_details:
                auth, bssid_from_netsh = get_authentication_and_bssid(essid)
                network_details[essid] = (auth, bssid_from_netsh)  # Store the details in the dictionary
            else:
                auth, bssid_from_netsh = network_details[essid]  # Retrieve the stored details

            # Display the information
            print(f"{bssid_from_netsh:<20} {essid:<30} {signal:<10} {auth:<30}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    live_scan()  # Start the live scan
