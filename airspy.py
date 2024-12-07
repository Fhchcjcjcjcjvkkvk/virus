import time
from pywifi import PyWiFi, const, Profile
import os
from datetime import datetime

def scan_networks():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Assuming you want the first wireless interface

    # Start scanning
    iface.scan()
    time.sleep(2)  # Wait for scan to complete
    scan_results = iface.scan_results()

    return scan_results

def print_scan_results(scan_results):
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the screen before printing new data
    print(f"CH  1 ][ Elapsed: {elapsed_time()} ][ {datetime.now().strftime('%Y-%m-%d %H:%M')}  ]")
    print(f"{'BSSID':<20} {'PWR':<5} {'ENC':<5} {'CIPHER':<7} {'AUTH':<5} ESSID")
    
    for network in scan_results:
        bssid = network[0]
        signal_strength = network[3]
        encryption = network[4]
        cipher = network[5]
        auth = network[6]
        essid = network[1]

        # Format encryption and other details (this part depends on how your network reports them)
        print(f"{bssid:<20} {signal_strength:<5} {encryption:<5} {cipher:<7} {auth:<5} {essid}")

def elapsed_time():
    if not hasattr(elapsed_time, "start_time"):
        elapsed_time.start_time = time.time()  # Initialize start time
    return f"{int(time.time() - elapsed_time.start_time) // 60}m {int(time.time() - elapsed_time.start_time) % 60}s"

def main():
    while True:
        scan_results = scan_networks()
        print_scan_results(scan_results)
        time.sleep(5)  # Adjust the update interval as needed

if __name__ == "__main__":
    main()
