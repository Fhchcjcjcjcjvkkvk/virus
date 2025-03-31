import argparse
import pyshark

def extract_psk_and_bssid(pcap_file):
    capture = pyshark.FileCapture(pcap_file, display_filter="wpa")
    bssid = None
    psk = None

    for packet in capture:
        if hasattr(packet, 'wpa'):
            # Check if this packet contains a WPA handshake or encrypted PSK information
            if hasattr(packet.wpa, 'eapol'):
                eapol = packet.wpa.eapol
                if "Key Data" in eapol:
                    psk = eapol["Key Data"]
                    if not bssid:
                        bssid = packet.wlan.bssid
                    break  # Once PSK and BSSID are found, break loop

    if bssid and psk:
        print(f"BSSID: {bssid}")
        print(f"PSK: {psk}")
    else:
        print("No WPA PSK information found in the capture file.")

def main():
    parser = argparse.ArgumentParser(description="Extract BSSID and PSK from WPA capture file")
    parser.add_argument("pcap_file", help="Path to the capture file (.pcap or .cap)")

    args = parser.parse_args()
    pcap_file = args.pcap_file

    extract_psk_and_bssid(pcap_file)

if __name__ == "__main__":
    main()
