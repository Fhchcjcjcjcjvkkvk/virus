import subprocess
import re

def get_available_networks():
    try:
        # Execute the netsh command to show available networks
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                                capture_output=True, text=True, check=True)
        networks_output = result.stdout
        
        networks = []
        network = {}

        for line in networks_output.splitlines():
            line = line.strip()
            
            # Match SSID
            if line.startswith("SSID"):
                if network:  # If a network is already parsed, store it and reset
                    networks.append(network)
                    network = {}
                network["SSID"] = line.split(":")[1].strip() if ":" in line else None
            
            # Match BSSID
            elif "BSSID" in line:
                network.setdefault("BSSIDs", []).append(line.split(":")[1].strip())
            
            # Match signal strength
            elif "Signal" in line:
                signal_match = re.search(r"(\d+)%", line)
                if signal_match:
                    network["Signal Strength"] = int(signal_match.group(1))
            
            # Match Channel
            elif "Channel" in line:
                network["Channel"] = line.split(":")[1].strip()

        # Add the last network if not already added
        if network:
            networks.append(network)

        return networks

    except subprocess.CalledProcessError as e:
        print("Error executing netsh command:", e)
        return []

# Fetch and print available networks
if __name__ == "__main__":
    available_networks = get_available_networks()
    for idx, network in enumerate(available_networks, start=1):
        print(f"Network {idx}:")
        print(f"  SSID: {network.get('SSID', 'N/A')}")
        print(f"  BSSIDs: {', '.join(network.get('BSSIDs', []))}")
        print(f"  Signal Strength: {network.get('Signal Strength', 'N/A')}%")
        print(f"  Channel: {network.get('Channel', 'N/A')}")
        print()
