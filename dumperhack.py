import pywifi
from pywifi import const
import time
from datetime import datetime

def print_header(channel, elapsed_time):
    """Print the header of the table."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
    print(f" CH  {channel} ][ Elapsed: {elapsed_time} mins ][ {current_time}")
    print(" " * 80)
    print(" BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC  CIPHER AUTH ESSID")
    print("-" * 80)

def get_security_info(network):
    """Get the encryption, cipher, and authentication type."""
    if network.akm[0] == const.AKM_TYPE_NONE:
        return "Open", "", ""
    elif network.akm[0] == const.AKM_TYPE_WPA2PSK:
        return "WPA2", "CCMP", "PSK"
    elif network.akm[0] == const.AKM_TYPE_WPAPSK:
        return "WPA", "TKIP", "PSK"
    elif network.akm[0] == const.AKM_TYPE_WPA3SAE:
        return "WPA3", "CCMP", "SAE"
    else:
        return "Unknown", "Unknown", "Unknown"

def scan_networks():
    """Scan for Wi-Fi networks and print them in a formatted table."""
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    iface.scan()  # Start scanning
    time.sleep(2)  # Wait for the scan results
    scan_results = iface.scan_results()

    for network in scan_results:
        bssid = network.bssid
        pwr = network.signal  # Signal strength in dBm
        channel = network.channel
        essid = network.ssid
        enc, cipher, auth = get_security_info(network)
        
        print(f" {bssid:17} {pwr:4}      120      50    0   {channel:2}  54   {enc:4} {cipher:4}  {auth:4} {essid}")

def main():
    """Main function to display networks."""
    elapsed_time = 0
    channel = 6  # Default channel (not used in Windows but for display)

    try:
        while True:
            print_header(channel, elapsed_time)
            scan_networks()
            elapsed_time += 1
            time.sleep(10)  # Scan interval
    except KeyboardInterrupt:
        print("\nStopping scan...")

if __name__ == "__main__":
    main()
