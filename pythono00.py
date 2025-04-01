import pyshark
from passlib.hash import pbkdf2_sha1
import hashlib

# Extract handshake from .cap file using PyShark
def extract_handshake(file_path):
    capture = pyshark.FileCapture(file_path, display_filter="eapol")

    eapol_packets = []
    for packet in capture:
        if 'eapol' in packet:
            eapol_packets.append(packet)

    if len(eapol_packets) >= 2:
        return eapol_packets[-2], eapol_packets[-1]
    else:
        raise ValueError("Handshake packets not found.")

# Extract PMK from the PSK, SSID, and EAPOL data
def derive_pmk(password, ssid, eapol_2, eapol_3):
    # Extract key material (simplified for clarity; needs real implementation)
    ap_mac = eapol_2.wlan.ta  # AP MAC address from EAPOL 2
    client_mac = eapol_2.wlan.sa  # Client MAC address from EAPOL 3

    # Prepare the PBKDF2 input material
    ssid_bytes = ssid.encode('utf-8')
    ap_mac_bytes = bytes.fromhex(ap_mac.replace(":", ""))
    client_mac_bytes = bytes.fromhex(client_mac.replace(":", ""))

    # Generate PMK using PBKDF2-HMAC-SHA1
    pmk = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), ssid_bytes, 4096, dklen=32)
    return pmk

# Check if the derived key matches the MIC (Message Integrity Code) from EAPOL packets
def check_psk(pmk, eapol_3):
    # Extract the MIC from EAPOL 3 packet
    mic = bytes.fromhex(eapol_3.eapol.key_mic)
    # Compare the derived PMK with the MIC
    return pmk[:16] == mic  # This is a simplified check for demonstration.

def crack_psk(capture_file, ssid, wordlist):
    eapol_2, eapol_3 = extract_handshake(capture_file)
    
    # Loop through the wordlist and try each password
    for password in wordlist:
        print(f"Trying password: {password}")
        pmk = derive_pmk(password, ssid, eapol_2, eapol_3)

        if check_psk(pmk, eapol_3):
            print(f"Password found: {password}")
            return password

    print("Password not found in wordlist.")
    return None

if __name__ == "__main__":
    capture_file = "wpa.cap"
    ssid = "test"
    
    # Load wordlist
    wordlist = ["password1", "biscotte", "letmein"]  # Example wordlist; load from a file in practice
    
    found_password = crack_psk(capture_file, ssid, wordlist)

    if found_password:
        print(f"PSK (Password) found: {found_password}")
    else:
        print("No matching PSK found.")
