import argparse
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Auth, Dot11AssoReq, Dot11Elt
import binascii


def extract_psk_handshake(pcap_file):
    """
    Identifies and extracts PSK handshakes from the pcap file.
    Returns BSSID and PSK if found.
    """
    pcap = rdpcap(pcap_file)

    bssid = None
    psk = None

    # Loop through the packets in the capture file
    for packet in pcap:
        if packet.haslayer(Dot11):
            # Check for Beacon frame (network info)
            if packet.type == 0 and packet.subtype == 8:  # Beacon
                bssid = packet[Dot11].addr3
            # Look for Authentication and Association Request packets
            elif packet.type == 0 and packet.subtype == 11:  # Authentication (for PSK)
                auth_packet = packet
                if auth_packet.haslayer(Dot11Elt):
                    for elt in auth_packet[Dot11Elt]:
                        if elt.ID == 221:  # WPA/RSN Element, may contain PSK
                            psk = binascii.hexlify(elt.info).decode('utf-8')
            # PMKID and PSK handling can be added here as needed

    if bssid and psk:
        print(f"BSSID: {bssid}")
        print(f"PSK: {psk}")
    else:
        print("No PSK Handshake found.")
        

def extract_pmkid(pcap_file):
    """
    Identifies and extracts PMKID from the pcap file.
    Returns BSSID and PMKID if found.
    """
    pcap = rdpcap(pcap_file)

    bssid = None
    pmkid = None

    # Loop through the packets in the capture file
    for packet in pcap:
        if packet.haslayer(Dot11):
            # Look for PMKID packets (usually from RSN/PMKID exchange)
            if packet.type == 2 and packet.subtype == 4:  # PMKID Response
                if packet.haslayer(Dot11Elt):
                    bssid = packet[Dot11].addr2
                    pmkid = binascii.hexlify(packet[Dot11Elt].info).decode('utf-8')

    if bssid and pmkid:
        print(f"BSSID: {bssid}")
        print(f"PMKID: {pmkid}")
    else:
        print("No PMKID found.")


def main():
    parser = argparse.ArgumentParser(description="Extract PSK or PMKID from a pcap capture file.")
    parser.add_argument("file", help="Path to the pcap or cap file to analyze.")
    args = parser.parse_args()

    try:
        # First, try extracting PSK handshake
        print("Checking for PSK handshake...")
        extract_psk_handshake(args.file)

        # If no PSK, try extracting PMKID
        print("\nChecking for PMKID...")
        extract_pmkid(args.file)

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
