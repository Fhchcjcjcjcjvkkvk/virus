import subprocess
import re

def scan_wifi_networks():
    # Run the command to get WiFi information
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)

    if result.returncode != 0:
        print("Error scanning for networks.")
        return

    # Regular expression patterns to extract the ESSID, BSSID, and RSSI
    essid_pattern = re.compile(r"SSID \d+ : (.+)")
    bssid_pattern = re.compile(r"BSSID \d+ : ([\da-fA-F:]+)")
    rssi_pattern = re.compile(r"Signal\s+:\s+(\d+)")
    
    # Extract network details
    essids = essid_pattern.findall(result.stdout)
    bssids = bssid_pattern.findall(result.stdout)
    rssis = rssi_pattern.findall(result.stdout)
    
    # Print the results
    print(f"{'ESSID':<30}{'BSSID':<20}{'RSSI (Signal Strength)'}")
    print("="*60)
    for essid, bssid, rssi in zip(essids, bssids, rssis):
        print(f"{essid:<30}{bssid:<20}{rssi}")

if __name__ == "__main__":
    scan_wifi_networks()
