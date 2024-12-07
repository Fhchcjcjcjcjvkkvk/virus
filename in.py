import sys
from scapy.all import sniff, Dot11, Dot11Elt, EAPOL, wrpcap
import subprocess
import time

# Global list to store EAPOL packets
eapol_packets = []

def packet_handler(pkt):
    """
    Function to handle incoming packets.
    Capture only EAPOL frames from the specified AP.
    """
    if pkt.haslayer(EAPOL):
        # Check if the packet is from the target AP (using its MAC address)
        if pkt[Dot11].addr2 == ap_mac:  # Assuming AP MAC address is in address 2
            eapol_packets.append(pkt)
            print(f"Captured EAPOL packet from {ap_mac}.")

def capture_eapol(interface, channel, output_file):
    """
    Function to capture EAPOL packets from the specified interface and channel
    and write them to a .pcap file.
    """
    # Set the channel using netsh (you may need to install netsh or use a different method)
    print(f"Setting channel to {channel} on {interface}...")
    subprocess.run(f"netsh wlan set hostednetwork channel={channel}", shell=True)
    
    # Start sniffing on the given interface
    print(f"Sniffing for EAPOL packets on {interface}...")
    sniff(iface=interface, prn=packet_handler, store=0, timeout=60)  # Timeout for 60 seconds

    # Write captured packets to a .pcap file
    if eapol_packets:
        print(f"Writing {len(eapol_packets)} packets to {output_file}.pcap...")
        wrpcap(output_file, eapol_packets)
    else:
        print("No EAPOL packets captured.")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python capture_eapol.py <AP MAC> <interface> <channel> <output_file>")
        sys.exit(1)

    ap_mac = sys.argv[1]   # AP MAC address to capture from
    interface = sys.argv[2]  # Interface in monitor mode (e.g., wlan0mon or Wi-Fi adapter)
    channel = int(sys.argv[3])  # Channel to monitor
    output_file = sys.argv[4]  # Output file for .pcap

    capture_eapol(interface, channel, output_file)
