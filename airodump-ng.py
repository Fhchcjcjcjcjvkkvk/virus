import argparse
import scapy.all as scapy

def extract_psk_from_handshake(pcap_file, ssid):
    # Load packets from the pcap file
    packets = scapy.rdpcap(pcap_file)
    
    # Find the EAPOL packets related to the given SSID
    eapol_packets = []
    for pkt in packets:
        if pkt.haslayer(scapy.EAPOL) and pkt.haslayer(scapy.Dot11):
            if pkt[scapy.Dot11].info.decode() == ssid:
                eapol_packets.append(pkt)
    
    if len(eapol_packets) < 2:
        print("Insufficient EAPOL packets found. Unable to extract PSK.")
        return
    
    # Assuming the second EAPOL packet is part of the handshake
    print(f"Identified PSK handshake for SSID: {ssid}")
    
    # Extract encrypted PSK from the EAPOL packets
    encrypted_psk = eapol_packets[1][scapy.EAPOL].load.hex()  # Using .load to get the payload

    print(f"Encrypted PSK: {encrypted_psk}")

def main():
    parser = argparse.ArgumentParser(description="Extract PSK from WPA handshake.")
    parser.add_argument("pcap_file", help="Path to the .pcap or .cap file")
    parser.add_argument("ssid", help="SSID of the network")
    
    args = parser.parse_args()
    
    extract_psk_from_handshake(args.pcap_file, args.ssid)

if __name__ == "__main__":
    main()
