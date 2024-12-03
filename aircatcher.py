import pyshark
import argparse
from collections import defaultdict
import time

def print_status(message):
    """Prints the status message to the console."""
    print(message)

def capture_handshake(bssid, interface, output_file):
    """
    Captures a Wi-Fi handshake and saves it to a .cap file using PyShark.
    """
    print_status("[Searching...]")
    
    # Track beacon statistics
    networks = defaultdict(lambda: {"encryption": "Unknown", "beacons": 0})

    def packet_handler(pkt):
        """Handles incoming packets to identify and capture handshake frames or beacons."""
        if hasattr(pkt, 'dot11'):
            # Process beacon frames
            if 'Beacon' in pkt.dot11:
                bssid = pkt.addr2
                encryption = pkt.wlan_crypto if hasattr(pkt, 'wlan_crypto') else "Unknown"
                networks[bssid]["encryption"] = encryption
                networks[bssid]["beacons"] += 1

                # Print BSSID, beacon count, and encryption
                print(f"Beacon: BSSID: {bssid}, Beacons: {networks[bssid]['beacons']}, Encryption: {networks[bssid]['encryption']}")
            
            # Capture EAPOL handshake packets (WPA/WPA2)
            if 'EAPOL' in pkt:
                if pkt.addr2 == bssid:
                    print_status("[Handshake captured]")
                    # Write the captured packet to the output .cap file
                    with open(output_file, 'ab') as f:
                        f.write(pkt.get_raw_packet())
                    return True  # Stop sniffing after capturing handshake
        return False

    # Start sniffing using PyShark on the specified interface
    capture = pyshark.LiveCapture(interface=interface, bpf_filter="wlan type mgt or wlan type data")  # Filter management and data frames

    # Set the callback function for each packet
    capture.apply_on_packets(packet_handler)

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="Capture Wi-Fi handshake with PyShark")
    parser.add_argument("-w", "--write", required=True, help="Output file for captured handshake (.cap)")
    parser.add_argument("--bssid", required=True, help="Target BSSID for handshake capture")
    parser.add_argument("interface", help="Network interface for monitoring")
    args = parser.parse_args()

    # Run the handshake capture
    capture_handshake(args.bssid, args.interface, args.write)
