import subprocess
import re

def get_wifi_networks():
    try:
        # Execute the netsh command
        output = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True, text=True, encoding='utf-8')
        
        networks = []
        network = {}
        
        # Parse the output
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID"):
                # Start of a new network
                if network:
                    networks.append(network)
                network = {
                    "ESSID": line.split(":")[1].strip(),
                    "BSSIDs": []
                }
            elif line.startswith("BSSID"):
                bssid = line.split(":")[1].strip()
                network["BSSIDs"].append({
                    "BSSID": bssid,
                    "Channel": None,
                    "Signal Strength": None
                })
            elif "Signal" in line and "Strength" in line:
                signal = line.split(":")[1].strip()
                if network and network["BSSIDs"]:
                    network["BSSIDs"][-1]["Signal Strength"] = signal
            elif "Channel" in line:
                channel = line.split(":")[1].strip()
                if network and network["BSSIDs"]:
                    network["BSSIDs"][-1]["Channel"] = channel
        
        # Append the last network if necessary
        if network:
            networks.append(network)
        
        return networks
    except subprocess.CalledProcessError as e:
        print("Failed to execute netsh command:", e)
        return []

# Fetch and display Wi-Fi networks
wifi_networks = get_wifi_networks()
for net in wifi_networks:
    print(f"Network Name (ESSID): {net['ESSID']}")
    for bssid in net["BSSIDs"]:
        print(f"  BSSID: {bssid['BSSID']}")
        print(f"  Channel: {bssid['Channel']}")
        print(f"  Signal Strength: {bssid['Signal Strength']}")
