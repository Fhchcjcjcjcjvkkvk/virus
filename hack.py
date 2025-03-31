import hashlib
import hmac
import binascii
import argparse
from tqdm import tqdm
from scapy.all import rdpcap, EAPOL, Dot11

# PBKDF2-HMAC-SHA1 function
def derive_psk(ssid, password):
    return hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32)

# MIC verification function
def verify_mic(psk, anonce, snonce, ap_mac, client_mac, eapol_frame, mic):
    pmk = psk  # Pairwise Master Key (PMK)
    key_data = b"Pairwise key expansion" + min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    ptk = hmac.new(pmk, key_data, hashlib.sha1).digest()[:32]  # Pairwise Transient Key (PTK)
    mic_calc = hmac.new(ptk, eapol_frame, hashlib.sha1).digest()[:16]
    return mic_calc == mic

# Function to extract handshake from a .cap file
def extract_handshake(cap_file):
    cap = rdpcap(cap_file)
    ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame = None, None, None, None, None, None, None
    
    for packet in cap:
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8 and ssid is None:  # Beacon frame
            ssid = packet.info.decode(errors='ignore')
            print(f"[+] Found SSID: {ssid}")
        
        if packet.haslayer(EAPOL):
            print(f"[+] Found EAPOL frame from {packet.addr2} to {packet.addr1}")
            if anonce is None and packet.FCfield & 2:  # AP to Client (Message 1)
                anonce = packet.payload.load[13:45]
                ap_mac = binascii.unhexlify(packet.addr2.replace(':', ''))
                print(f"[+] Found ANonce: {binascii.hexlify(anonce).decode()}")
            elif snonce is None and packet.FCfield & 1:  # Client to AP (Message 2)
                snonce = packet.payload.load[13:45]
                client_mac = binascii.unhexlify(packet.addr1.replace(':', ''))
                mic = packet.payload.load[-18:-2]
                eapol_frame = packet.payload.load[:]
                eapol_frame = eapol_frame[:len(eapol_frame) - 18] + b'\x00' * 16  # Zeroing MIC
                print(f"[+] Found SNonce: {binascii.hexlify(snonce).decode()}")
    
    if all([ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame]):
        return ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame
    else:
        print("[!] Handshake not found!")
        exit(1)

# WPA cracking function
def crack_wpa(cap_file, wordlist_file):
    ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame = extract_handshake(cap_file)
    
    print(f"[+] Targeting network: {ssid}")
    with open(wordlist_file, 'r', encoding='utf-8') as f:
        passwords = [line.strip() for line in f.readlines()]
    
    for password in tqdm(passwords, desc="Testing passwords"):
        print(f"Trying passphrase: {password}")
        psk = derive_psk(ssid, password)
        if verify_mic(psk, anonce, snonce, ap_mac, client_mac, eapol_frame, mic):
            print(f"\n[+] KEY FOUND! [ {password} ]")
            exit(0)
    
    print("[-] KEY NOT FOUND")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WPA/WPA2 Password Recovery Tool")
    parser.add_argument("cap_file", help=".cap file containing handshake")
    parser.add_argument("-P", "--passwords", help="Wordlist file", required=True)
    
    args = parser.parse_args()
    
    crack_wpa(args.cap_file, args.passwords)
