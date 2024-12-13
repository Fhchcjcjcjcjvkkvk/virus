import time
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon
from collections import defaultdict

# Function to process each packet
def packet_handler(pkt):
    # We are only interested in Beacon frames (type 0 and subtype 8)
    if pkt.haslayer(Dot11Beacon):
        essid = pkt[Dot11].info.decode(errors="ignore")
        if essid != "":
            # Increment the beacon count for this ESSID
            beacon_counts[essid] += 1

# Function to start sniffing
def sniff_wifi(interface):
    print("Starting packet sniffing on interface:", interface)
    scapy.sniff(iface=interface, prn=packet_handler, store=0)

# Function to display the ESSID and beacon counts live
def display_counts():
    while True:
        # Clear the console (works on Windows, may vary on other systems)
        print("\033[H\033[J", end="")
        print("ESSID\t\t\tBeacon Count")
        print("-" * 40)
        # Print each ESSID with its beacon count
        for essid, count in beacon_counts.items():
            print(f"{essid}\t\t{count}")
        time.sleep(1)

# Main function
if __name__ == "__main__":
    # Specify the network interface (example: 'wlan0' or 'Wi-Fi')
    interface = input("Enter the interface name (e.g., Wi-Fi): ").strip()
    beacon_counts = defaultdict(int)

    # Start packet sniffing and displaying counts in separate threads
    from threading import Thread
    sniff_thread = Thread(target=sniff_wifi, args=(interface,))
    display_thread = Thread(target=display_counts)

    sniff_thread.start()
    display_thread.start()

    sniff_thread.join()
    display_thread.join()
