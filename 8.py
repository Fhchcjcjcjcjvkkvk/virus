import argparse
import pyshark
import time

# Function to sniff for EAPOL packets and print the WPA handshake
def sniff_eapol_packets(ap_mac, channel):
    print(f"Sniffing for WPA handshakes on AP {ap_mac} (Channel {channel})...")

    # Specify the capture interface on Windows (you'll need to adjust this to your interface)
    interface = "WiFi"  # Replace with your wireless interface name
    capture_filter = f"ether host {ap_mac} and eapol"  # BPF filter for EAPOL packets
    
    # Start capturing EAPOL packets
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter)

    print("Listening for EAPOL packets...")

    # Capture packets for 60 seconds (adjust as needed)
    capture.sniff(timeout=60)

    for packet in capture:
        if 'eapol' in packet:
            print(f"WPA Handshake found for BSSID: {ap_mac}")
            break  # Stop after the first WPA handshake

if __name__ == "__main__":
    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="AirHunter - Sniff WPA Handshakes")
    parser.add_argument("-a", "--ap", required=True, help="AP MAC address")
    parser.add_argument("-c", "--channel", required=True, type=int, help="Channel number")

    args = parser.parse_args()

    # Call the sniff function with the provided AP MAC and channel
    sniff_eapol_packets(args.ap, args.channel)
