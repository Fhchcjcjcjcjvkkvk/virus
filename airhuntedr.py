import time
from pywifi import PyWiFi, const, Profile

# Function to scan networks and display their details
def scan_wifi_networks():
    wifi = PyWiFi()  # Initialize the Wi-Fi interface
    iface = wifi.interfaces()[0]  # Use the first interface (e.g., your wireless card)
    
    iface.scan()  # Start scanning
    time.sleep(2)  # Wait a few seconds for the scan to complete
    
    scan_results = iface.scan_results()  # Get the scan results
    
    if scan_results:
        print("Available Networks:")
        print(f"{'SSID':<30} {'BSSID':<20} {'Signal Strength (dBm)'}")
        print("-" * 60)
        
        for network in scan_results:
            ssid = network.ssid
            bssid = network.bssid
            signal_strength = network.signal
            print(f"{ssid:<30} {bssid:<20} {signal_strength} dBm")
    else:
        print("No networks found.")

# Run the Wi-Fi scanning function
scan_wifi_networks()
