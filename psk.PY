import pyshark
import hashlib
import argparse

def extract_handshake_data(pcap_file):
    """ Extrahuje potřebná data z pcap nebo cap souboru """
    cap = pyshark.FileCapture(pcap_file, display_filter='eapol')
    
    eapol_packets = []
    client_mac = None
    ap_mac = None
    anonce = None
    snonce = None
    
    # Extrahujeme pakety EAPOL
    for packet in cap:
        if 'EAPOL' in packet:
            eapol_packets.append(packet)
            
            # Identifikace MAC adresy AP a klienta
            if packet.wlan.ta != "ff:ff:ff:ff:ff:ff":  # Kontrola pro adresu AP
                ap_mac = packet.wlan.ta
            if packet.wlan.sa != "ff:ff:ff:ff:ff:ff":  # Kontrola pro MAC klienta
                client_mac = packet.wlan.sa
            
            # Získání ANonce a SNonce z EAPOL
            if hasattr(packet.eapol, 'anonce'):
                anonce = packet.eapol.anonce
            if hasattr(packet.eapol, 'snonce'):
                snonce = packet.eapol.snonce
                
    return client_mac, ap_mac, eapol_packets, anonce, snonce

def derive_psk(ssid, password):
    """ Derivace PSK pomocí PBKDF2-HMAC-SHA1 """
    ssid = ssid.encode('utf-8')
    password = password.encode('utf-8')
    
    # Derivace PSK z password a SSID
    psk = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, dklen=32)
    return psk

def main():
    parser = argparse.ArgumentParser(description="Extrahuj data z WPA/WPA2 handshaku a derivuj PSK.")
    parser.add_argument('-P', '--wordlist', help="Cesta k wordlist souboru pro PSK derivaci", required=True)
    parser.add_argument('capture', help="PCAP nebo CAP soubor", type=str)
    parser.add_argument('ssid', help="SSID cílové sítě", type=str)
    
    args = parser.parse_args()
    
    # Extrahování dat z pcap souboru
    client_mac, ap_mac, eapol_packets, anonce, snonce = extract_handshake_data(args.capture)
    
    if client_mac and ap_mac:
        print(f"Client MAC: {client_mac}")
        print(f"AP MAC: {ap_mac}")
        print(f"ANonce: {anonce}")
        print(f"SNonce: {snonce}")
    else:
        print("Chybí potřebná data v pcap souboru.")
        return
    
    # Nyní načteme wordlist pro PSK derivaci
    with open(args.wordlist, 'r') as wordlist_file:
        for line in wordlist_file:
            password = line.strip()
            print(f"Testování hesla: {password}")
            
            # Derivace PSK pro každý password v wordlistu
            psk = derive_psk(args.ssid, password)
            print(f"Derivovaný PSK: {psk.hex()}")

if __name__ == "__main__":
    main()
