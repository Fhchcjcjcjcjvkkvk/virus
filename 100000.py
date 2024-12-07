import argparse
import pyshark
import time
import os

# Funkce pro sniffování WPA handshakes na specifikovaném kanálu a BSSID
def sniff_eapol_packets(ap_mac, channel, output_file):
    print(f"Sniffing for WPA handshakes on AP {ap_mac} (Channel {channel})...")

    # Získání správného rozhraní
    iface = "WiFi"  # Nahraďte správným názvem vašeho rozhraní
    print(f"Using interface: {iface}")

    # Přepnutí Wi-Fi adaptéru na specifikovaný kanál (pokud je to podporováno)
    set_channel(channel)

    # Filtr pro EAPOL pakety (EtherType 0x888e)
    capture_filter = f"ether proto 0x888e and ether host {ap_mac}"

    # Nastavení PyShark pro live capture
    capture = pyshark.LiveCapture(interface=iface, bpf_filter=capture_filter)

    # Pokud je zadán soubor, uložíme capture do souboru
    if output_file:
        capture.output_file = output_file
        print(f"Saving capture to {output_file}...")

    # Zachytávání paketů
    print("Listening for EAPOL packets...")

    # Zahájíme capture na 60 sekund
    capture.sniff(timeout=60)

    # Kontrola, zda byly zachyceny EAPOL pakety
    handshake_found = False
    for packet in capture:
        if 'eapol' in packet:
            print(f"WPA Handshake found for BSSID: {ap_mac}")
            handshake_found = True
            break  # Když najdeme první WPA handshake, zastavíme sniffování

    if not handshake_found:
        print(f"No WPA handshake found for BSSID: {ap_mac}")

# Funkce pro přepnutí kanálu (pouze pro kompatibilní adaptéry)
def set_channel(channel):
    # Pomocí Scapy můžeme přepnout kanál pro Wi-Fi adaptér
    print(f"Setting channel to {channel}")
    try:
        os.system(f"netsh interface wlan set channel {channel}")
    except Exception as e:
        print(f"Error setting channel: {e}")

if __name__ == "__main__":
    # Argumenty z příkazové řádky
    parser = argparse.ArgumentParser(description="AirHunter - Sniff WPA Handshakes like airodump-ng using PyShark")
    parser.add_argument("-a", "--ap", required=True, help="AP MAC address")
    parser.add_argument("-c", "--channel", type=int, required=True, help="Channel number to monitor")
    parser.add_argument("--write", type=str, help="Filename to save the capture (e.g. capture.pcap)")

    args = parser.parse_args()

    # Zavolání funkce pro sniffování WPA handshakes
    sniff_eapol_packets(args.ap, args.channel, args.write)
