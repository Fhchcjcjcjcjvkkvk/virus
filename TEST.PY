import argparse
from scapy.all import rdpcap, Dot11Beacon, Dot11ProbeResp

def extract_essid(pcap_file):
    packets = rdpcap(pcap_file)
    essid_list = set()
    
    for packet in packets:
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            essid = packet.info.decode(errors='ignore')
            if essid:
                essid_list.add(essid)
    
    if essid_list:
        print("ESSID(s) found:")
        for essid in essid_list:
            print(f"- {essid}")
    else:
        print("No ESSID found in the provided capture file.")

def main():
    parser = argparse.ArgumentParser(description="Extract ESSID(s) from a pcap file.")
    parser.add_argument("pcap_file", help="Path to the .pcap or .cap file")
    args = parser.parse_args()
    extract_essid(args.pcap_file)

if __name__ == "__main__":
    main()
