from scapy.all import sniff, Dot11, Dot11Beacon, wrpcap
import argparse
import os
from collections import defaultdict

def print_status(message):
    """Prints the status message to the console."""
    print(message)

def capture_handshake(bssid, interface, output_file):
    """
    Captures a Wi-Fi handshake and saves it to a .cap file.
    """
    print_status("[Searching...]")
    
    # Track beacon statistics
    networks = defaultdict(lambda: {"encryption": "Unknown", "beacons": 0})

    def packet_handler(pkt):
        """
        Handles incoming packets to identify and capture handshake frames or beacons.
        """
        if pkt.haslayer(Dot11):
            # Process beacon frames
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt.addr2
                encryption = pkt[Dot11Beacon].network_stats().get("crypto", "Unknown")
                networks[bssid]["encryption"] = ", ".join(encryption)
                networks[bssid]["beacons"] += 1
                
                # Print BSSID, beacon count, and encryption
                print(f"Beacon: BSSID: {bssid}, Beacons: {networks[bssid]['beacons']}, Encryption: {networks[bssid]['encryption']}")
            
            # Check for EAPOL handshake packets
            if pkt.addr2 == bssid and pkt.type == 2:  # Type 2 is data frames (EAPOL handshake)
                print_status("[Handshake captured]")
                # Save to .cap file
                wrpcap(output_file, [pkt], append=True)
                return True  # Stop sniffing after capturing handshake

        return False

    # Start sniffing packets (no channel switching on Windows)
    sniff(iface=interface, prn=packet_handler, stop_filter=packet_handler, store=False)

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="Capture Wi-Fi handshake")
    parser.add_argument("-w", "--write", required=True, help="Output file for captured handshake (.cap)")
    parser.add_argument("--bssid", required=True, help="Target BSSID for handshake capture")
    parser.add_argument("interface", help="Network interface for monitoring")
    args = parser.parse_args()

    # Run the handshake capture
    capture_handshake(args.bssid, args.interface, args.write)
