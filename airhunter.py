import time
from pywifi import PyWiFi, const, Profile

def scan_networks():
    wifi = PyWiFi()  # Create a PyWiFi object
    iface = wifi.interfaces()[0]  # Get the first wireless interface
    
    iface.scan()  # Start scanning
    time.sleep(2)  # Wait for the scan to complete

    networks = iface.scan_results()  # Get the scan results

    if not networks:
        print("No networks found.")
        return

    print("Available Networks:\n")
    for network in networks:
        # Extract relevant data from each network
        ssid = network.ssid
        bssid = network.bssid
        rssi = network.signal  # RSSI value (signal strength)
        beacon_period = network.beacon_period  # Beacon period (in time units)

        print(f"SSID: {ssid}")
        print(f"BSSID: {bssid}")
        print(f"RSSI: {rssi} dBm")
        print(f"Beacon Period: {beacon_period} (time units)")
        print("-" * 40)

if __name__ == "__main__":
    scan_networks()
