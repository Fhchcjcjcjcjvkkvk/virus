import time
import pyshark
from collections import defaultdict
import threading

# Dictionary to store ESSID and the beacon count
beacon_counts = defaultdict(int)

# Function to process each packet from PyShark
def packet_handler(pkt):
    # Only consider Beacon frames
    if hasattr(pkt, 'wlan') and 'beacon' in pkt.wlan.fc_type_str:
        essid = pkt.wlan.ssid if hasattr(pkt.wlan, 'ssid') else 'Unknown'
        beacon_counts[essid] += 1

# Function to start sniffing using PyShark
def sniff_wifi(interface):
    print(f"Starting packet sniffing on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface, display_filter="wlan.fc.type_subtype == 0x08")
    for pkt in capture.sniff_continuously():
        packet_handler(pkt)

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
    # Ask the user for the interface name
    interface = input("Enter the interface name (e.g., Wi-Fi): ").strip()

    # Start displaying counts in a separate thread
    display_thread = threading.Thread(target=display_counts)
    display_thread.start()

    # Run PyShark capture in the main thread
    sniff_wifi(interface)

    display_thread.join()  # Wait for the display thread to finish
