import subprocess
import re

def get_wifi_networks():
    # Run the 'netsh wlan show networks mode=bssid' command to get Wi-Fi networks
    result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True)
    output = result.stdout
    
    # Regular expression patterns for extracting network information
    network_pattern = re.compile(r"SSID\s*:\s*(?P<ESSID>.+?)\r?\n.*?BSSID\s*:\s*(?P<BSSID>[\w:]+)\r?\n.*?Channel\s*:\s*(?P<Channel>\d+)\r?\n.*?Signal\s*:\s*(?P<SignalStrength>\d+)")
    
    networks = []
    
    # Iterate through all the matched networks in the output
    for match in network_pattern.finditer(output):
        essid = match.group("ESSID").strip()
        bssid = match.group("BSSID")
        channel = match.group("Channel")
        signal_strength = match.group("SignalStrength")
        
        # Store the extracted information in a list
        networks.append({
            "ESSID": essid,
            "BSSID": bssid,
            "Channel": channel,
            "SignalStrength": signal_strength + " dBm"
        })
    
    return networks

def display_networks(networks):
    if not networks:
        print("No Wi-Fi networks found.")
    else:
        print(f"{'ESSID':<30} {'BSSID':<20} {'Channel':<10} {'Signal Strength':<15}")
        print("-" * 75)
        for network in networks:
            print(f"{network['ESSID']:<30} {network['BSSID']:<20} {network['Channel']:<10} {network['SignalStrength']:<15}")

if __name__ == "__main__":
    networks = get_wifi_networks()
    display_networks(networks)
