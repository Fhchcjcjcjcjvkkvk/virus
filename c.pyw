import scapy.all as scapy
import time
import sys
import os

def sniff_packets(interface):
    print(f"Sniffing on {interface}...\n")
    scapy.sniff(iface=interface, store=False, prn=packet_handler)

def packet_handler(packet):
    if packet.haslayer(scapy.Dot11):
        if packet.type == 0 and packet.subtype == 8:
            # Beacon Frame
            bssid = packet[scapy.Dot11].addr3
            essid = packet[scapy.Dot11Elt].info.decode()
            signal_strength = packet.dBm_AntSignal if packet.dBm_AntSignal else 'N/A'
            channel = packet[scapy.Dot11Beacon].network_stats().get("channel")
            encryption = "WPA2" if "WPA2" in essid else "WEP" if "WEP" in essid else "OPN"
            cipher = "TKIP" if encryption == "WPA2" else "WEP"  # Just an example, needs better logic for cipher
            print(f"BSSID: {bssid}\t ESSID: {essid}\t CH: {channel}\t ENC: {encryption}\t CIPHER: {cipher}\t Signal: {signal_strength} dBm")
        elif packet.type == 2 and packet.subtype == 4:
            # WPA Handshake
            handshake = packet[scapy.Dot11].addr1
            print(f"WPA Handshake detected: {handshake}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python airhunter.py -a <ap_mac> <interface>")
        sys.exit(1)

    if sys.argv[1] == "-a":
        ap_mac = sys.argv[2]
        interface = sys.argv[3]
        sniff_packets(interface)
    else:
        print("Invalid arguments. Use: python airhunter.py -a <ap_mac> <interface>")

if __name__ == "__main__":
    main()
