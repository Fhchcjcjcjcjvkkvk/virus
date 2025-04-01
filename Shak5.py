import hashlib
import hmac
import pyshark
import binascii

# PBKDF2-HMAC-SHA1 function
def pbkdf2_hmac_sha1(password, ssid, iterations=4096, dklen=32):
    salt = ssid.encode() + b'\x00'
    return hashlib.pbkdf2_hmac('sha1', password.encode(), salt, iterations, dklen)

# Function to extract SSID from beacon/probe response frames
def extract_ssid(capture_file):
    cap = pyshark.FileCapture(capture_file, display_filter='wlan_mgt.ssid')
    for packet in cap:
        if hasattr(packet, 'wlan_mgt') and hasattr(packet.wlan_mgt, 'ssid'):
            return packet.wlan_mgt.ssid
    return None

# Function to parse EAPOL handshake
def parse_handshake(capture_file):
    cap = pyshark.FileCapture(capture_file, display_filter='eapol')
    eapol_frames = [packet for packet in cap]
    return eapol_frames if len(eapol_frames) >= 3 else None

# Extract key data from the EAPOL frame
def extract_key_data(eapol_frame):
    return binascii.unhexlify(eapol_frame.eapol.key_data.replace(':', ''))  # Convert hex to bytes

# Function to crack the PSK
def crack_psk_from_capture(capture_file, dictionary):
    ssid = extract_ssid(capture_file)
    if not ssid:
        print("SSID not found in capture.")
        return None

    eapol_frames = parse_handshake(capture_file)
    if not eapol_frames:
        print("Insufficient EAPOL frames.")
        return None

    eapol_key_data = extract_key_data(eapol_frames[-1])

    for password in dictionary:
        psk_candidate = pbkdf2_hmac_sha1(password, ssid)
        if psk_candidate == eapol_key_data:
            print(f"Found PSK: {password}")
            return password

    print("PSK not found in dictionary.")
    return None

# Example usage
capture_file = 'Shak.cap'  # Change this to your .cap file
dictionary = ['password123', 'peklovpn34', 'letmein']

crack_psk_from_capture(capture_file, dictionary)
