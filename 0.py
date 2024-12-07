import subprocess
import re

def get_networks():
    try:
        # Run the netsh command to list Wi-Fi networks
        result = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"], shell=True, text=True)
        
        networks = []
        network = {}
        for line in result.splitlines():
            line = line.strip()
            
            # Match network name (SSID)
            ssid_match = re.match(r"^SSID\s\d+\s*:\s(.*)", line)
            if ssid_match:
                if network:  # Save the previous network if it exists
                    networks.append(network)
                    network = {}
                network['SSID'] = ssid_match.group(1)
            
            # Match BSSID
            bssid_match = re.match(r"^BSSID\s\d+\s*:\s(.*)", line)
            if bssid_match:
                network.setdefault('BSSIDs', []).append(bssid_match.group(1))
            
            # Match signal strength
            signal_match = re.match(r"^Signal\s*:\s(\d+)%", line)
            if signal_match:
                network['Signal Strength'] = signal_match.group(1) + '%'
            
            # Match channel
            channel_match = re.match(r"^Channel\s*:\s(\d+)", line)
            if channel_match:
                network['Channel'] = channel_match.group(1)
            
            # Beacon frames (not directly available in netsh, example added for structure)
            # If you use specialized tools like Wireshark or pyshark, you can extract beacon frame data.
            # Placeholder for illustrative purposes:
            network['Beacons'] = "N/A"

        # Append the last network if it exists
        if network:
            networks.append(network)

        return networks
    except subprocess.CalledProcessError as e:
        print("Error running netsh command:", e)
        return []

def display_networks(networks):
    if not networks:
        print("No networks found.")
        return

    for i, network in enumerate(networks, 1):
        print(f"Network {i}:")
        print(f"  SSID: {network.get('SSID', 'N/A')}")
        print(f"  BSSIDs: {', '.join(network.get('BSSIDs', []))}")
        print(f"  Signal Strength: {network.get('Signal Strength', 'N/A')}")
        print(f"  Channel: {network.get('Channel', 'N/A')}")
        print(f"  Beacons: {network.get('Beacons', 'N/A')}")
        print("-" * 30)

if __name__ == "__main__":
    networks = get_networks()
    display_networks(networks)
