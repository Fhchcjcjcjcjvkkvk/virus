import sys
import time
from scapy.all import *

# Function to count beacons per ESSID
def process_packet(packet, essid_dict):
    if packet.haslayer(Dot11):
        # Check if the packet is a beacon frame (type = 0, subtype = 8)
        if packet.type == 0 and packet.subtype == 8:
            essid = packet[Dot11Beacon].network_stats().get('essid', None)
            if essid:
                if essid not in essid_dict:
                    essid_dict[essid] = 0
                essid_dict[essid] += 1

# Function to print the live table of ESSIDs and beacon counts
def print_live(essid_dict):
    # Clear the screen (for live update)
    print("\033c", end="")
    print(f"{'ESSID':<35}{'Beacons'}")
    print("-" * 45)
    
    for essid, count in essid_dict.items():
        print(f"{essid:<35}{count}")

# Main function to start sniffing
def start_sniffing(interface):
    # Dictionary to store ESSID -> beacon count
    essid_dict = {}

    print(f"Sniffing on interface {interface}...\n")
    print_live(essid_dict)

    # Start sniffing indefinitely
    sniff(iface=interface, prn=lambda packet: process_packet(packet, essid_dict), store=0)

# Main entry point
if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != '-i':
        print("Usage: python airsniff.py -i <interface>")
        sys.exit(1)

    interface = sys.argv[2]

    try:
        start_sniffing(interface)
    except Exception as e:
        print(f"Error: {e}")
