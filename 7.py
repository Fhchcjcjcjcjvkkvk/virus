import argparse
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Auth, Dot11AssoReq, Dot11Elt
import pyshark

def extract_psk_from_pcap(pcap_file):
    pcap = pyshark.FileCapture(pcap_file, display_filter="wlan.fc.type_subtype == 0x08 or wlan.fc.type_subtype == 0x0b")
    psk_found = False
    bssid = None
    psk = None

    for pkt in pcap:
        if hasattr(pkt, 'wlan') and hasattr(pkt.wlan, 'addr2'):
            bssid = pkt.wlan.addr2
            if hasattr(pkt.wlan, 'eapol') and pkt.wlan.eapol.type == '0':
                if hasattr(pkt.wlan, 'eapol'):
                    eapol = pkt.wlan.eapol
                    if hasattr(eapol, 'key') and len(eapol.key) > 0:
                        psk = eapol.key
                        psk_found = True
                        break
    
    if psk_found:
        print(f"BSSID: {bssid}")
        print(f"PSK: {psk.hex()}")
    else:
        print("PSK not found in the capture file.")
        
def main():
    parser = argparse.ArgumentParser(description="Extract PSK from WPA2 Capture")
    parser.add_argument("file", help="Path to the .pcap or .cap file")
    
    args = parser.parse_args()

    extract_psk_from_pcap(args.file)

if __name__ == "__main__":
    main()
