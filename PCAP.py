import argparse
from scapy.all import rdpcap

def extract_psk(pcap_file, ssid):
    packets = rdpcap(pcap_file)
    psk = None
    
    # Logic to identify PSK from the capture file
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            if pkt.info.decode() == ssid:
                if pkt.haslayer(RSNCipherSuite):
                    psk = pkt[RSNCipherSuite].ciphertext
                    break
    
    return psk

def main():
    parser = argparse.ArgumentParser(description="Extract PSK from a .pcap or .cap file for a given SSID.")
    parser.add_argument("pcap_file", help="The .pcap or .cap file to analyze.")
    parser.add_argument("ssid", help="The SSID to search for in the capture file.")
    
    args = parser.parse_args()
    
    psk = extract_psk(args.pcap_file, args.ssid)
    
    if psk:
        print(f"Encrypted PSK: {psk}")
    else:
        print("No PSK found for the given SSID.")

if __name__ == "__main__":
    main()
