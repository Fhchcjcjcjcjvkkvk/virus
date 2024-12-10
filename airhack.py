import argparse
import time
import pyshark
from datetime import datetime

# Function to capture traffic and detect WPA handshake
def capture_traffic(bssid, interface, duration, output_file):
    print(f"Starting capture on interface: {interface}")
    print(f"Monitoring BSSID: {bssid} for {duration} seconds")

    # Start packet capture with pyshark
    capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
    
    beacon_count = 0
    eapol_count = 0
    handshake_found = False
    ap_bssid = None
    ap_essid = None
    ap_encryption = None

    # Set capture timeout based on duration
    capture.sniff(timeout=duration)

    # Process packets
    for packet in capture:
        try:
            # Check for Beacon frames
            if 'wlan_mgt' in packet and hasattr(packet.wlan, 'bssid'):
                if packet.wlan.bssid == bssid:
                    beacon_count += 1
                    if ap_bssid is None:
                        ap_bssid = packet.wlan.bssid
                        ap_essid = packet.wlan.ssid if hasattr(packet.wlan, 'ssid') else 'Hidden'
                        ap_encryption = packet.wlan.encryption_type if hasattr(packet.wlan, 'encryption_type') else 'Unknown'

            # Check for EAPOL frames (WPA Handshake detection)
            if 'eapol' in packet:
                eapol_count += 1
                handshake_found = True

        except AttributeError:
            continue

    # Output results in tabular format
    print("\nCapture Results:")
    print("-" * 60)
    print(f"{'Beacon Count':<15} {'Encryption':<12} {'BSSID':<20} {'ESSID':<20}")
    print("-" * 60)
    print(f"{beacon_count:<15} {ap_encryption:<12} {ap_bssid:<20} {ap_essid:<20}")
    print("-" * 60)
    
    if handshake_found:
        print("WPA handshake found!")
    else:
        print("No WPA handshake found!")

    print(f"Total beacon frames captured: {beacon_count}")
    print(f"Total EAPOL frames captured: {eapol_count}")
    print(f"Capture saved to {output_file}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Capture WPA handshakes from a specific BSSID")
    parser.add_argument('-a', '--bssid', required=True, help="Target BSSID")
    parser.add_argument('-W', '--output', required=True, help="Output capture file (.cap)")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to use")
    parser.add_argument('-t', '--time', type=int, default=120, help="Capture duration in seconds (default 120 seconds)")

    args = parser.parse_args()

    # Run the traffic capture
    capture_traffic(args.bssid, args.interface, args.time, args.output)

if __name__ == '__main__':
    main()
