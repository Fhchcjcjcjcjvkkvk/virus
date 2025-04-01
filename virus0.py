import argparse
import pyshark
from passlib.hash import pbkdf2_sha1
import hashlib
import binascii

# Function to extract handshake from pcap file
def extract_handshake(file):
    capture = pyshark.FileCapture(file, display_filter="eapol")
    eapol_frames = []
    ssids = set()

    for packet in capture:
        if 'eapol' in packet:
            eapol_frames.append(packet)
            
            # Safely check for the wlan layer and extract the SSID
            if 'wlan' in packet:
                try:
                    ssid = packet.wlan.ssid
                    ssids.add(ssid)
                except AttributeError:
                    # If ssid is not available, fall back to bssid or other info
                    if 'wlan_bssid' in packet:
                        ssid = packet.wlan_bssid
                        ssids.add(ssid)
                    else:
                        print("No SSID or BSSID available in the packet.")
    
    capture.close()
    
    if len(eapol_frames) < 2:
        print("Handshake not found. Need at least two EAPOL frames.")
        return None, []

    return eapol_frames, list(ssids)

# Function to parse the selected SSID from the capture file
def parse_handshake(eapol_frames, selected_ssid):
    for packet in eapol_frames:
        if 'wlan' in packet and (getattr(packet.wlan, 'ssid', None) == selected_ssid or getattr(packet.wlan, 'bssid', None) == selected_ssid):
            ssid = packet.wlan.ssid if 'ssid' in packet.wlan else packet.wlan_bssid
            eapol_data = binascii.unhexlify(packet.eapol.key.iv)  # Example of extracting data
            return ssid, eapol_data
    print("Selected SSID not found in the capture.")
    return None, None

# Function to compute PMK and compare with the captured handshake
def compute_pmk(ssid, psk_candidate):
    # Compute PMK using PBKDF2-HMAC-SHA1 (as aircrack-ng does)
    pmk = pbkdf2_sha1.using(rounds=4096).hash(ssid.encode('utf-8') + psk_candidate.encode('utf-8'))
    return pmk

# Function to attempt the dictionary attack
def dictionary_attack(capture_file, wordlist):
    print(f"Loading capture file: {capture_file}")
    eapol_frames, ssids = extract_handshake(capture_file)

    if not eapol_frames:
        return

    if not ssids:
        print("No SSIDs found in the capture file.")
        return

    # Display SSID options and let the user choose one
    print("\nAvailable SSIDs:")
    for i, ssid in enumerate(ssids, start=1):
        print(f"{i}. {ssid}")

    # User selects SSID by number
    selected_number = int(input("\nEnter the number of the SSID you want to use: ")) - 1
    if selected_number < 0 or selected_number >= len(ssids):
        print("Invalid selection.")
        return
    
    selected_ssid = ssids[selected_number]
    print(f"Selected SSID: {selected_ssid}")

    # Parse the handshake for the selected SSID
    ssid, psk_eapol = parse_handshake(eapol_frames, selected_ssid)
    if not ssid:
        return

    with open(wordlist, 'r') as wordlist_file:
        for line in wordlist_file:
            psk_candidate = line.strip()
            print(f"Trying PSK: {psk_candidate}")

            pmk = compute_pmk(ssid, psk_candidate)
            # Here, compare PMK with the PSK in the EAPOL packet (mock comparison for demonstration)
            if pmk == psk_eapol:
                print(f"PSK found: {psk_candidate}")
                return

    print("No matching PSK found in the wordlist.")

# Main function to handle argument parsing
def main():
    parser = argparse.ArgumentParser(description="WPA2 PSK Recovery Tool using PyShark and Passlib")
    parser.add_argument('-f', '--file', required=True, help="Path to the .cap or .pcap file")
    parser.add_argument('-w', '--wordlist', required=True, help="Path to the wordlist file for dictionary attack")

    args = parser.parse_args()

    dictionary_attack(args.file, args.wordlist)

if __name__ == "__main__":
    main()
