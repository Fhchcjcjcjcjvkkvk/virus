import argparse
import pyshark
import time
import subprocess

# Function to set the channel (requires root/admin privileges)
def set_channel(interface, channel):
    print(f"Setting interface {interface} to channel {channel}...")
    try:
        subprocess.run(["netsh", "interface", "wifi", "set", "channel", str(channel)], check=True)
        print(f"Channel {channel} set successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error setting channel: {e}")

# Function to sniff for EAPOL packets and print the WPA handshake
def sniff_eapol_packets(ap_mac, channel, output_file):
    print(f"Sniffing for WPA handshakes on AP {ap_mac} (Channel {channel})...")

    # Specify the capture interface on Windows (you'll need to adjust this to your interface)
    interface = "Wi-Fi"  # Replace with your wireless interface name
    capture_filter = f"ether host {ap_mac} and eapol"  # BPF filter for EAPOL packets
    
    # Set the wireless interface to the specified channel (only works on Windows for certain adapters)
    set_channel(interface, channel)

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
    parser.add_argument("-c", "--channel", required=True, type=int, help="Channel number")
    parser.add_argument("--write", type=str, help="Filename to save the capture (e.g. capture.pcap)")

    args = parser.parse_args()

    # Call the sniff function with the provided AP MAC, channel, and output file
    sniff_eapol_packets(args.ap, args.channel, args.write)
