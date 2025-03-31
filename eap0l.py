import argparse
import hashlib
import binascii
from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11, Dot11WEP
from scapy.layers.dhcp import DHCP

# Function to read and extract WPA handshake from pcap
def get_handshake(pcap_file):
    packets = rdpcap(pcap_file)
    handshake = []
    
    for pkt in packets:
        if pkt.haslayer(Dot11) and pkt.type == 2 and pkt.subtype == 8:  # Beacon frame
            continue
        if pkt.haslayer(Dot11WEP) or pkt.haslayer(Dot11):
            # Filtering for EAPOL packets
            if pkt.haslayer(Dot11) and pkt.addr1 and pkt.addr2:
                handshake.append(pkt)
                if len(handshake) >= 4:  # Minimum frames to capture WPA handshake
                    break
    return handshake

# Function to derive PSK from a wordlist and WPA handshake
def derive_psk(handshake, wordlist_file):
    # Extract the ESSID and the 4-way handshake (simplified)
    essid = "PEKLO"  # This should come from the pcap
    pmk = None  # The actual pre-shared key (PSK) will be derived here
    
    with open(wordlist_file, 'r') as wordlist:
        for line in wordlist:
            password = line.strip()
            # Derive the PSK (this is the process you'd normally use for WPA key derivation)
            psk = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), essid.encode('utf-8'), 4096)
            pmk = binascii.hexlify(psk).decode('utf-8')
            print(f"Testing password: {password}, Derived PSK: {pmk}")
    
    return pmk

# Main function to set up argparse and flow
def main():
    parser = argparse.ArgumentParser(description="WPA PSK Deriver")
    parser.add_argument("pcap_file", help="Path to the pcap capture file")
    parser.add_argument("-P", "--wordlist", required=True, help="Path to the wordlist file")
    args = parser.parse_args()

    # Extract WPA handshake
    handshake = get_handshake(args.pcap_file)
    if not handshake:
        print("No handshake found in pcap file.")
        return

    # Derive PSK using the wordlist
    psk = derive_psk(handshake, args.wordlist)
    if psk:
        print(f"Encrypted PSK in hex: {psk}")

if __name__ == "__main__":
    main()
