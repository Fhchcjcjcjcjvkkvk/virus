import argparse
from scapy.all import *
import pyshark
import time

# Funkce pro sniffování WPA handshakes a celého provozu na specifikovaném kanálu a BSSID pomocí Scapy
def sniff_eapol_packets(ap_mac, channel, iface, output_file):
    print(f"Sniffing for WPA handshakes and all traffic on AP {ap_mac} (Channel {channel}) on interface {iface}...")

    # Zajistěte, že váš Wi-Fi adaptér je v monitorovacím režimu a nastavte kanál v externím nástroji (např. Wireshark, Acrylic Wi-Fi)

    # Nastavení rozhraní na správné Wi-Fi rozhraní
    conf.iface = iface  # Nastavíme rozhraní zadané uživatelem

    # Filtr pro všechny pakety a EAPOL pakety (EtherType 0x888e)
    bpf_filter = f"ether proto 0x888e or ip or udp or tcp or icmp"  # Filtr pro EAPOL a všechny IP pakety

    print("Listening for all traffic and EAPOL packets...")

    # Zachytávání paketů
    packets = sniff(count=100, filter=bpf_filter, iface=iface, timeout=60)  # Počet paketů a časový limit na 60 sekund

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
    parser.add_argument("-i", "--iface", required=True, help="Wi-Fi interface to use")
    parser.add_argument("--write", type=str, help="Filename to save the capture (e.g. capture.pcap)")

    args = parser.parse_args()

    # Zavolání funkce pro sniffování WPA handshakes a celého provozu
    sniff_eapol_packets(args.ap, args.channel, args.iface, args.write)

    # Pokud byl zadán soubor, provedeme analýzu zachycených paketů
    if args.write:
        analyze_capture_file(args.write)
