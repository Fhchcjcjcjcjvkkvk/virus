import argparse
from scapy.all import *
import time

# Funkce pro sniffování WPA handshakes na specifikovaném kanálu a BSSID
def sniff_eapol_packets(ap_mac, channel, output_file):
    print(f"Sniffing for WPA handshakes on AP {ap_mac} (Channel {channel})...")

    # Přepnutí Wi-Fi adaptéru na specifikovaný kanál
    conf.iface = "WiFi"  # Nahraďte názvem vašeho rozhraní
    set_channel(channel)

    # Filtr pro EAPOL pakety (EtherType 0x888e)
    bpf_filter = f"ether proto 0x888e and ether host {ap_mac}"

    # Zachytávání paketů
    print("Listening for EAPOL packets...")
    
    packets = sniff(count=100, filter=bpf_filter, timeout=60)  # Počet paketů a časový limit na 60 sekund

    # Pokud je zadán soubor, uložíme capture do souboru
    if output_file:
        wrpcap(output_file, packets)
        print(f"Capture saved to {output_file}")

    # Kontrola, zda byly zachyceny EAPOL pakety
    handshake_found = False
    for packet in packets:
        if packet.haslayer(EAPOL):
            print(f"WPA Handshake found for BSSID: {ap_mac}")
            handshake_found = True
            break  # Když najdeme první WPA handshake, zastavíme sniffování
    
    if not handshake_found:
        print(f"No WPA handshake found for BSSID: {ap_mac}")

# Funkce pro přepnutí kanálu
def set_channel(channel):
    # Pomocí Scapy můžeme přepnout kanál pro Wi-Fi adaptér
    conf.iface = "WiFi"  # Nahraďte názvem vašeho rozhraní
    os.system(f"netsh interface wlan set channel {channel}")

if __name__ == "__main__":
    # Argumenty z příkazové řádky
    parser = argparse.ArgumentParser(description="AirHunter - Sniff WPA Handshakes like airodump-ng")
    parser.add_argument("-a", "--ap", required=True, help="AP MAC address")
    parser.add_argument("-c", "--channel", type=int, required=True, help="Channel number to monitor")
    parser.add_argument("--write", type=str, help="Filename to save the capture (e.g. capture.pcap)")

    args = parser.parse_args()

    # Zavolání funkce pro sniffování WPA handshakes
    sniff_eapol_packets(args.ap, args.channel, args.write)
