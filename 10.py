import argparse
import pyshark
import time

# Function to sniff for EAPOL packets and print the WPA handshake
def sniff_eapol_packets(ap_mac, output_file):
    print(f"Sniffing for WPA handshakes on AP {ap_mac}...")

    # Specify the capture interface on Windows (you'll need to adjust this to your interface)
    interface = "WiFi"  # Replace with your wireless interface name
    capture_filter = f"ether host {ap_mac} and eapol"  # BPF filter for EAPOL packets
    
    # Start capturing EAPOL packets
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter)

    # If a filename is provided, save the capture to a file
    if output_file:
        print(f"Saving capture to {output_file}...")
        capture.output_file = output_file

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
    parser.add_argument("--write", type=str, help="Filename to save the capture (e.g. capture.pcap)")

    args = parser.parse_args()

    # Call the sniff function with the provided AP MAC and output file
    sniff_eapol_packets(args.ap, args.write)
