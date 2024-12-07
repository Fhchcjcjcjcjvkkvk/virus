import argparse
from scapy.all import *
import pyshark
import os
import time

# Funkce pro sniffování WPA handshakes na specifikovaném kanálu a BSSID pomocí Scapy
def sniff_eapol_packets(ap_mac, channel, output_file):
    print(f"Sniffing for WPA handshakes on AP {ap_mac} (Channel {channel})...")

    # Nastavení Wi-Fi adaptéru na správný kanál
    set_channel(channel)
    
    # Filtr pro EAPOL pakety (EtherType 0x888e)
    bpf_filter = f"ether proto 0x888e and ether host {ap_mac}"

    print("Listening for EAPOL packets...")

    # Zachytávání paketů
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

# Funkce pro přepnutí kanálu na Windows (pomocí TShark)
def set_channel(channel):
    # Pokud používáte TShark a máte správně nastavený monitorovací režim, můžete použít TShark pro přepnutí kanálu
    print(f"Switching to channel {channel}...")
    os.system(f"tshark -i WiFi --channel {channel}")

# Funkce pro analýzu zachycených paketů pomocí PyShark
def analyze_capture_file(file_name):
    print(f"Analyzing capture file {file_name}...")
    capture = pyshark.FileCapture(file_name)
    for packet in capture:
        if 'eapol' in packet:
            print(f"Found EAPOL packet: {packet}")
            # Zde můžete přidat další logiku pro analýzu paketů
        time.sleep(1)  # Pauza mezi zpracováním paketů

if __name__ == "__main__":
    # Argumenty z příkazové řádky
    parser = argparse.ArgumentParser(description="Wi-Fi WPA Handshake Sniffer")
    parser.add_argument("-a", "--ap", required=True, help="AP MAC address")
    parser.add_argument("-c", "--channel", type=int, required=True, help="Channel number to monitor")
    parser.add_argument("--write", type=str, help="Filename to save the capture (e.g. capture.pcap)")

    args = parser.parse_args()

    # Zavolání funkce pro sniffování WPA handshakes
    sniff_eapol_packets(args.ap, args.channel, args.write)

    # Pokud byl zadán soubor, provedeme analýzu zachycených paketů
    if args.write:
        analyze_capture_file(args.write)
