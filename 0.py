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
    parser.add_argument("--interface", required=True, help="Network interface to capture packets.")
    parser.add_argument("--bssid", required=True, help="BSSID of the target network.")
    parser.add_argument("--write", required=True, help="File to save the captured packets (e.g., capture.pcap).")

    args = parser.parse_args()

    capture_eapol(args.interface, args.bssid, args.write)
