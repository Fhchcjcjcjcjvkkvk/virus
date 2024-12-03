import pyshark
import argparse
from collections import defaultdict
import time
from scapy.all import wrpcap

def print_status(message):
    """Prints the status message to the console."""
    print(message)

def capture_handshake(bssid, interface, output_file):
    """
    Captures a Wi-Fi handshake and saves it to a .pcap file using PyShark and Scapy.
    """
    print_status("[Searching...]")
    
    # Track beacon statistics
    networks = defaultdict(lambda: {"encryption": "Unknown", "beacons": 0})

    # Create a list to store captured packets for saving later
    captured_packets = []

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
                    # Save the captured packet to the list
                    captured_packets.append(pkt)
                    # Once handshake is captured, stop sniffing
                    return True
        return False

    # Start sniffing using PyShark on the specified interface
    capture = pyshark.LiveCapture(interface=interface, bpf_filter="wlan type mgt or wlan type data")  # Filter management and data frames

    # Set the callback function for each packet
    capture.apply_on_packets(packet_handler)

    # After capture, save the packets to a pcap file
    if captured_packets:
        print_status(f"Saving {len(captured_packets)} captured packets to {output_file}")
        wrpcap(output_file, captured_packets)

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="Capture Wi-Fi handshake with PyShark")
    parser.add_argument("-w", "--write", required=True, help="Output file for captured handshake (.pcap)")
    parser.add_argument("--bssid", required=True, help="Target BSSID for handshake capture")
    parser.add_argument("interface", help="Network interface for monitoring")
    args = parser.parse_args()

    # Run the handshake capture
    capture_handshake(args.bssid, args.interface, args.write)
