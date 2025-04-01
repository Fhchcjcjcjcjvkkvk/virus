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
    cap = pyshark.FileCapture(pcap_file, display_filter="eapol || wlan_mgt")

    ssid = None
    ap_mac, client_mac = None, None
    anonce, snonce, mic = None, None, None
    key_replay_counter = None

    print("[*] Scanning capture file...")

    for i, pkt in enumerate(cap):
        print(f"[*] Packet {i+1}: {pkt.highest_layer}")

        # Extract SSID from beacon/probe response
        if hasattr(pkt, "wlan_mgt") and hasattr(pkt.wlan_mgt, "ssid"):
            ssid = pkt.wlan_mgt.ssid
            print(f"[+] SSID Found: {ssid}")

        # Extract WPA Handshake Information
        if hasattr(pkt, "eapol"):
            print(f"[+] EAPOL Packet Found (Frame {i+1})")
            eapol_layer = pkt.eapol

            key_info = getattr(eapol_layer, "key_info", None)
            if key_info is None:
                print("[!] Skipping EAPOL packet - missing key_info")
                continue  # Skip packet if key_info is missing
            
            if int(key_info, 16) & 0x0080:  # Check if message contains MIC
                ap_mac = getattr(pkt.wlan, "bssid", None)
                client_mac = getattr(pkt.wlan, "sa", None)
                anonce = getattr(eapol_layer, "key_nonce", None)
                snonce = getattr(eapol_layer, "wlan_mgt.wpa_key_nonce", None)
                mic = getattr(eapol_layer, "key_mic", None)
                key_replay_counter = getattr(eapol_layer, "key_replay_counter", None)

                print(f"[*] AP MAC: {ap_mac}, Client MAC: {client_mac}")
                print(f"[*] ANonce: {anonce}")
                print(f"[*] SNonce: {snonce}")
                print(f"[*] MIC: {mic}")
                print(f"[*] Replay Counter: {key_replay_counter}")

                if ap_mac and client_mac and anonce and snonce and mic:
                    print("[+] Full Handshake Captured")
                    break  # Exit loop after finding a valid handshake

    cap.close()

    if not (ssid and anonce and snonce and mic and ap_mac and client_mac):
        print("[!] Incomplete handshake found. Debug output:")
        print(f"    - SSID: {ssid}")
        print(f"    - AP MAC: {ap_mac}")
        print(f"    - Client MAC: {client_mac}")
        print(f"    - ANonce: {anonce}")
        print(f"    - SNonce: {snonce}")
        print(f"    - MIC: {mic}")
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WPA/WPA2 Handshake Debugging Tool")
    parser.add_argument("-c", "--cap", required=True, help="Path to the .cap file")

    args = parser.parse_args()

    handshake_data = extract_handshake(args.cap)
    if handshake_data:
        print("[+] Handshake extraction complete. Ready for cracking.")
    else:
        print("[-] Could not extract a valid handshake.")
