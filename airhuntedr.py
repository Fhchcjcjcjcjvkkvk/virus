import time
from pywifi import PyWiFi, const, Profile

# Function to scan available Wi-Fi networks
def scan_wifi():
    wifi = PyWiFi()  # Create an instance of PyWiFi
    iface = wifi.interfaces()[0]  # Get the first Wi-Fi interface (if you have more, adjust the index)

    # Start scanning for Wi-Fi networks
    iface.scan()
    time.sleep(2)  # Give some time for the scan to complete
    
    # Get the list of available networks
    networks = iface.scan_results()

    # Display available networks with ESSID and BSSID
    print(f"{'ESSID':<30} {'BSSID'}")
    print("="*50)
    for network in networks:
        essid = network.ssid
        bssid = network.bssid
        print(f"{essid:<30} {bssid}")
        
# Call the scan_wifi function
scan_wifi()
