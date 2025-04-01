import argparse
import pyshark

# Funkce pro extrakci informací z EAPOL paketu
def extract_handshake_info(cap_file):
    cap = pyshark.FileCapture(cap_file, display_filter="eapol")

    # Inicializace proměnných pro uchování informací
    ssid = None
    bssid = None
    client_mac = None
    anonce = None
    snonce = None
    mic = None

    for packet in cap:
        # Zkontroluj, zda paket obsahuje EAPOL
        if hasattr(packet, 'eapol') and hasattr(packet.eapol, 'key'):
            # Získání BSSID (MAC adresa přístupového bodu)
            if not bssid and hasattr(packet, 'wlan') and hasattr(packet.wlan, 'bssid'):
                bssid = packet.wlan.bssid

            # Získání SSID z beaconu (nebo z jiného zdroje)
            if not ssid and hasattr(packet, 'wlan') and hasattr(packet.wlan, 'ssid'):
                ssid = packet.wlan.ssid

            # Získání Client MAC (MAC adresa klienta)
            if not client_mac and hasattr(packet, 'wlan') and hasattr(packet.wlan, 'ta'):
                client_mac = packet.wlan.ta

            # Získání ANonce a SNonce
            if hasattr(packet.eapol, 'key'):
                if hasattr(packet.eapol.key, 'anonce') and not anonce:
                    anonce = packet.eapol.key.anonce
                if hasattr(packet.eapol.key, 'snonce') and not snonce:
                    snonce = packet.eapol.key.snonce

            # Získání MIC (Message Integrity Code)
            if hasattr(packet.eapol.key, 'mic') and not mic:
                mic = packet.eapol.key.mic

        # Pokud máme všechny potřebné informace, můžeme výstup napsat
        if ssid and bssid and client_mac and anonce and snonce and mic:
            print(f"SSID: {ssid}")
            print(f"BSSID: {bssid}")
            print(f"Client MAC: {client_mac}")
            print(f"ANonce: {anonce}")
            print(f"SNonce: {snonce}")
            print(f"MIC: {mic}")
            break  # Když máme vše, ukončíme loop

    if not (ssid and bssid and client_mac and anonce and snonce and mic):
        print("Nebyly nalezeny všechny potřebné informace!")

# Hlavní funkce pro parsování argumentů a spuštění skriptu
def main():
    # Nastavení argumentů
    parser = argparse.ArgumentParser(description="Extrahování WPA/WPA2 handshakes z .cap nebo .pcap souboru")
    parser.add_argument("-f", "--file", required=True, help="Cesta k .cap nebo .pcap souboru")
    args = parser.parse_args()

    # Zavolání funkce pro extrakci informací
    extract_handshake_info(args.file)

if __name__ == "__main__":
    main()
