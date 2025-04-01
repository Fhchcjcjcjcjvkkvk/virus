import pyshark
import binascii

def extract_handshake_data(pcap_file):
    # Otevřeme pcap soubor s filtrem na EAPOL pakety
    cap = pyshark.FileCapture(pcap_file, display_filter="eapol")

    # Inicializace proměnných pro uložení informací
    client_mac = None
    ap_mac = None
    mic = None
    ptk = None
    pmk = None
    eapol_hmac = None
    anonce = None
    snonce = None

    # Procházení paketů v pcap souboru
    for packet in cap:
        try:
            # Získání MAC adresy AP a klienta
            if 'wlan' in packet:
                if not ap_mac and packet.wlan.sa != packet.wlan.da:
                    ap_mac = packet.wlan.sa
                    client_mac = packet.wlan.da
                    print(f"AP MAC: {ap_mac}")
                    print(f"Client MAC: {client_mac}")

            # Získání MIC (Message Integrity Code)
            if 'eapol' in packet:
                if packet.eapol.message == "01":
                    mic = packet.eapol.key_mic
                    print(f"MIC: {mic}")

            # Získání eapol HMAC
            if 'eapol' in packet and hasattr(packet.eapol, 'key_hmac'):
                eapol_hmac = packet.eapol.key_hmac
                print(f"EAPOL HMAC: {eapol_hmac}")

            # Získání PTK (Pairwise Transient Key) a PMK (Pairwise Master Key)
            if 'eapol' in packet and hasattr(packet.eapol, 'key_iv'):
                ptk = packet.eapol.key_iv
                print(f"PTK: {ptk}")
                
                # PMK (Pairwise Master Key) je derivován z PSK a pre-shared secret, zde se použije kódování pro generování
                if hasattr(packet.eapol, 'key_nonce'):
                    pmk = packet.eapol.key_nonce
                    print(f"PMK: {pmk}")

            # Získání Anonce a Snonce (nonce hodnoty)
            if 'eapol' in packet:
                if hasattr(packet.eapol, 'key_nonce'):
                    if packet.wlan.sa == ap_mac:  # Pokud je AP odesílatel, je to Anonce
                        anonce = packet.eapol.key_nonce
                        print(f"Anonce: {binascii.hexlify(anonce)}")
                    elif packet.wlan.sa == client_mac:  # Pokud je klient odesílatel, je to Snonce
                        snonce = packet.eapol.key_nonce
                        print(f"Snonce: {binascii.hexlify(snonce)}")
                
        except AttributeError:
            continue

    # Uvolnění a uzavření capture
    cap.close()

# Zavolání funkce pro extrakci dat
extract_handshake_data('Shak.pcap')
