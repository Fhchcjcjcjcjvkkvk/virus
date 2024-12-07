import subprocess
import re

def get_available_networks():
    # Run the netsh command to get available networks with detailed info
    result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True)

    # Split the output into lines for easier parsing
    networks_info = result.stdout.splitlines()

    networks = []

    # Regular expressions to capture ESSID, BSSID, Channel, Signal strength (RSSI)
    essid_pattern = re.compile(r"SSID (\d+) : (.+)")
    bssid_pattern = re.compile(r"BSSID (\d+) : (.+)")
    channel_pattern = re.compile(r"Channel\s*: (\d+)")
    signal_pattern = re.compile(r"Signal\s*: (\d+)")

    network = {}

    # Iterate through each line and parse relevant information
    for line in networks_info:
        # Match ESSID
        essid_match = essid_pattern.search(line)
        if essid_match:
            if network:  # If a network was previously added, store it before moving on
                networks.append(network)
            network = {"ESSID": essid_match.group(2)}  # Initialize a new network dictionary

        # Match BSSID
        bssid_match = bssid_pattern.search(line)
        if bssid_match:
            network["BSSID"] = bssid_match.group(2)

        # Match Channel
        channel_match = channel_pattern.search(line)
        if channel_match:
            network["Channel"] = channel_match.group(1)

        # Match Signal strength (RSSI value, no percentage)
        signal_match = signal_pattern.search(line)
        if signal_match:
            network["Signal Strength (RSSI)"] = signal_match.group(1)  # RSSI value without percentage

    # Append the last network if present
    if network:
        networks.append(network)

    return networks

# Function to display networks
def display_networks(networks):
    print(f"{'ESSID':<30} {'BSSID':<20} {'Channel':<10} {'Signal Strength (RSSI)'}")
    print("="*80)
    
    for network in networks:
        # Safely retrieve values from network dictionary
        essid = network.get("ESSID", "N/A")
        bssid = network.get("BSSID", "N/A")
        channel = network.get("Channel", "N/A")
        signal_strength = network.get("Signal Strength (RSSI)", "N/A")
        
        print(f"{essid:<30} {bssid:<20} {channel:<10} {signal_strength}")

# Get available networks and display them
networks = get_available_networks()
display_networks(networks)
