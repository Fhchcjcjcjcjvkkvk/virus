import time
import os
import pywifi
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


# Function to get the maximum speed and explanation based on MB value
def get_max_speed_explanation(speed_mbps):
    # Explanation based on the speed (in Mbps)
    if speed_mbps <= 11:
        return f"{speed_mbps} Mbps - 802.11b"
    elif speed_mbps <= 22:
        return f"{speed_mbps} Mbps - 802.11b+"
    elif speed_mbps <= 54:
        return f"{speed_mbps} Mbps - 802.11g"
    elif speed_mbps <= 72:
        return f"{speed_mbps} Mbps - 802.11n"
    elif speed_mbps <= 150:
        return f"{speed_mbps} Mbps - 802.11n (High throughput)"
    elif speed_mbps <= 300:
        return f"{speed_mbps} Mbps - 802.11n (Dual Band)"
    elif speed_mbps <= 600:
        return f"{speed_mbps} Mbps - 802.11ac"
    else:
        return f"{speed_mbps} Mbps - 802.11ac (Very High throughput)"

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
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30} {'Max Speed':<30}")
        print("-" * 120)

        for network in networks:
            bssid = network.bssid  # Access the BSSID (MAC address) directly
            essid = network.ssid   # Access the ESSID (network name) directly
            signal = network.signal  # Access the signal strength directly

            # Get the authentication type using netsh for each ESSID
            auth = get_authentication(essid)
            
            # Assuming that `network` object provides the max speed, we simulate it here
            # In a real-world case, you may want to extract this value directly from network's attributes.
            max_speed = 54  # Placeholder for max speed (you might want to extract actual data)
            
            # Get the explanation for the max speed
            max_speed_explanation = get_max_speed_explanation(max_speed)

            # Display the information
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} {max_speed_explanation:<30}")

        time.sleep(5)  # Wait for 5 seconds before the next scan


if __name__ == "__main__":
    live_scan()  # Start the live scan
