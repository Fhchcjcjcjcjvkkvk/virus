import pyshark
import sys
import hashlib
import argparse

# Function to extract PMKID
def extract_pmkid(packet):
    if 'wlan_mgt' in packet and 'tag_number' in packet.wlan_mgt.field_names:
        # PMKID is part of the Management Frame, tag number 221 (0xDD)
        if packet.wlan_mgt.tag_number == '221':
            return packet.wlan.ta, packet.wlan_mgt.data
    return None, None

# Function to process WPA Handshake packets and extract PSK/PMKID
def extract_psk_or_pmkid(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="wlan.fc.type_subtype == 0x08")

    for packet in cap:
        # Check if packet contains WPA information
        if hasattr(packet, 'wlan') and hasattr(packet.wlan, 'addr2'):
            # Extract PMKID
            bssid, pmkid = extract_pmkid(packet)
            if pmkid:
                print(f"PMKID Detected\nBSSID: {bssid}")
                print(f"PMKID: {pmkid}")
                return

            # WPA Handshake (looking for EAPOL or other relevant data)
            if hasattr(packet, 'eapol'):
                bssid = packet.wlan.addr2
                print(f"PSK Detected\nBSSID: {bssid}")
                print("PSK: Real PSK extraction requires capturing the full handshake and cracking")
                return

    print("No PSK or PMKID found in this capture.")

def main():
    # Argument parsing with argparse
    parser = argparse.ArgumentParser(description="Extract PSK or PMKID from WPA capture file.")
    parser.add_argument('pcap_file', type=str, help="The path to the .pcap file containing the WPA handshake")
    args = parser.parse_args()

    # Call the extraction function with the provided .pcap file
    extract_psk_or_pmkid(args.pcap_file)

if __name__ == "__main__":
    main()
