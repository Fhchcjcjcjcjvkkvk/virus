from scapy.all import *
from collections import defaultdict
import time

# Dictionary to store the ESSID and the beacon count
beacon_counts = defaultdict(int)

def packet_handler(pkt):
    """
    Function to handle each packet
    - Looks for 802.11 Beacon frames (Management frame subtype 8).
    """
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
        if pkt.info:
            essid = pkt.info.decode(errors='ignore')
            beacon_counts[essid] += 1

def display_counts():
    """
    Function to print out the ESSID and beacon counts in columns
    """
    print("\nESSID".ljust(30) + "Beacons")
    print("-" * 40)
    for essid, count in beacon_counts.items():
        print(essid.ljust(30) + str(count).rjust(7))

def sniff_beacons(interface):
    """
    Start sniffing on the given interface for beacon frames
    """
    print(f"[*] Sniffing on interface {interface} for beacon frames...\n")
    try:
        sniff(iface=interface, prn=packet_handler, store=0, timeout=60)
    except Exception as e:
        print(f"Error: {e}")
        return

if __name__ == "__main__":
    # Replace 'YOUR_INTERFACE' with the name of your interface, e.g., 'wlan0'
    interface = input("Enter the interface to sniff (e.g., 'wlan0'): ").strip()

    try:
        while True:
            sniff_beacons(interface)
            display_counts()
            time.sleep(5)  # Delay between updates
    except KeyboardInterrupt:
        print("\n[*] Exiting...")

