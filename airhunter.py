import time
from pywifi import PyWiFi, const, Profile

def scan_networks():
    wifi = PyWiFi()
    
    # Get the first wireless interface (usually, the primary one)
    iface = wifi.interfaces()[0]
    
    # Start scanning for networks
    iface.scan()
    
    # Wait a few seconds for scan results to populate
    time.sleep(2)
    
    # Retrieve scan results
    scan_results = iface.scan_results()
    
    # Print out BSSID, ESSID, RSSI for each network found
    print("Scanning completed, here are the networks found:")
    print(f"{'BSSID':<20} {'ESSID':<30} {'RSSI':<5}")
    print("-" * 55)
    
    for network in scan_results:
        bssid = network.bssid
        essid = network.ssid
        rssi = network.signal  # RSSI value (signal strength)
        print(f"{bssid:<20} {essid:<30} {rssi:<5} dBm")

if __name__ == "__main__":
    print("Scanning for networks...")
    scan_networks()
