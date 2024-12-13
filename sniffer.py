import pyshark
import argparse
from colorama import init, Fore, Style

def main():
    # Initialize colorama
    init(autoreset=True)
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="A simple network sniffer to display HTTP and DNS requests.")
    parser.add_argument("-i", "--interface", required=True, help="The network interface to sniff on.")
    args = parser.parse_args()

    # Start live capture on the specified interface with broader filter
    try:
        print(f"Starting capture on interface: {args.interface}")
        # Broad filter for both HTTP and HTTPS traffic
        capture = pyshark.LiveCapture(interface=args.interface, display_filter="tcp port 80 or tcp port 443")

        # Process each packet
        for packet in capture.sniff_continuously():
            try:
                print("\n--- Packet Captured ---")
                if 'http' in packet:
                    print(Fore.MAGENTA + "HTTP Request:")
                    print(Fore.MAGENTA + f"Source: {packet.ip.src} -> Destination: {packet.ip.dst}")
                    print(Fore.MAGENTA + f"Request: {packet.http.request_method} {packet.http.host}{packet.http.request_uri}")
                    print(Fore.MAGENTA + f"User-Agent: {packet.http.get('User-Agent', 'N/A')}")
                    if packet.http.request_method == "POST" and hasattr(packet.http, 'file_data'):
                        print(Fore.MAGENTA + f"Form Data: {packet.http.file_data}")
                elif 'dns' in packet:
                    print(Fore.RED + "DNS Request:")
                    if hasattr(packet.dns, 'qry_name'):
                        print(Fore.RED + f"Query: {packet.dns.qry_name}")
                    else:
                        print(Fore.RED + "No DNS query name found.")
            except AttributeError as e:
                print(Fore.RED + f"Packet error: {e}")
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

if __name__ == "__main__":
    main()
