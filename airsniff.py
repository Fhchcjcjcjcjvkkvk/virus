import pyshark
import argparse
from colorama import init, Fore

def main():
    # Initialize colorama
    init(autoreset=True)
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="A simple network sniffer to display HTTP and DNS requests.")
    parser.add_argument("-i", "--interface", required=True, help="The network interface to sniff on.")
    args = parser.parse_args()

    # Start live capture on the specified interface
    try:
        print(f"Starting capture on interface: {args.interface}")
        capture = pyshark.LiveCapture(interface=args.interface, display_filter="http or dns")

        # Process each packet
        for packet in capture.sniff_continuously():
            try:
                if 'http' in packet:
                    print("\n" + Fore.RED + "--- HTTP Packet Captured ---")
                    print(f"Source: {packet.ip.src} -> Destination: {packet.ip.dst}")
                    print(f"Request: {packet.http.request_method} {packet.http.host}{packet.http.request_uri}")
                    print(f"User-Agent: {packet.http.get('User-Agent', 'N/A')}")
                    if packet.http.request_method == "POST" and hasattr(packet.http, 'file_data'):
                        print(f"Form Data: {packet.http.file_data}")
                elif 'dns' in packet:
                    print("\n" + Fore.GREEN + "--- DNS Packet Captured ---")
                    if hasattr(packet.dns, 'qry_name'):
                        print(f"Query: {packet.dns.qry_name}")
                    else:
                        print("No DNS query name found.")
            except AttributeError as e:
                print(f"Packet error: {e}")
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
