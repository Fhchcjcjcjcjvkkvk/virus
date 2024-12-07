import pyshark

def capture_eapol_handshake(pcap_file, bssid):
    print(f"Starting capture from file: {pcap_file} for BSSID: {bssid}")

    # Open the capture file
    cap = pyshark.FileCapture(pcap_file, display_filter=f'eapol and wlan.bssid == {bssid}')

    handshake_found = False

    # Loop through packets in the capture file
    for packet in cap:
        if 'eapol' in packet:
            # Check if the packet is part of the 4-way handshake
            print("WPA - Handshake found!")
            handshake_found = True
            break  # We found a handshake, exit the loop

    if not handshake_found:
        print("No WPA Handshake found in the capture.")

# Example usage: capture_eapol_handshake('capture.pcap', '88:78:74:87')

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Capture WPA 4-way handshake from a pcap file")
    parser.add_argument('--write', required=True, help="Path to the capture file (e.g., capture.pcap)")
    parser.add_argument('--bssid', required=True, help="Target BSSID (e.g., 88:78:74:87)")

    args = parser.parse_args()

    capture_eapol_handshake(args.write, args.bssid)
import pyshark
import argparse

def capture_eapol(interface, bssid, output_file):
    print(f"Starting capture on interface {interface} for BSSID {bssid}...")
    capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
    handshake_packets = []

    try:
        for packet in capture.sniff_continuously():
            # Check if the packet contains the EAPOL layer
            if 'EAPOL' in packet:
                # Check the source or destination address to match the target BSSID
                if packet.wlan.sa == bssid or packet.wlan.da == bssid:
                    print(f"EAPOL Packet captured: {packet}")
                    handshake_packets.append(packet)

                    # WPA Handshake detection: 4 packets should be captured
                    if len(handshake_packets) == 4:
                        print("WPA - Handshake found!")
                        break
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    finally:
        print(f"Capture saved to {output_file}.")
        capture.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture WPA Handshake from a network.")
    parser.add_argument("--interface", required=True, help="Network interface to capture packets (e.g., Wi-Fi).")
    parser.add_argument("--bssid", required=True, help="BSSID of the target network.")
    parser.add_argument("--write", required=True, help="File to save the captured packets (e.g., capture.pcap).")

    args = parser.parse_args()

    capture_eapol(args.interface, args.bssid, args.write)
