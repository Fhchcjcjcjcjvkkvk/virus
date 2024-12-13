import pyshark
import argparse
from colorama import init, Fore, Style

def main():
    # Initialize colorama
    init(autoreset=True)
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="A simple network sniffer to capture all HTTP POST data.")
    parser.add_argument("-i", "--interface", required=True, help="The network interface to sniff on.")
    args = parser.parse_args()

    # Start live capture on the specified interface with filter for TCP port 3000
    try:
        print(f"Starting capture on interface: {args.interface}")
        # Capture HTTP traffic on port 3000, filter for POST requests
        capture = pyshark.LiveCapture(interface=args.interface, display_filter="tcp port 3000 and http.request.method == POST")

        # Process each packet
        for packet in capture.sniff_continuously():
            try:
                # Check if the packet contains HTTP layer
                if 'http' in packet:
                    # Check if it's a POST request (usually for form submissions)
                    if packet.http.request_method == "POST":
                        print("\n--- POST Data Captured ---")
                        print(Fore.MAGENTA + f"Source: {packet.ip.src} -> Destination: {packet.ip.dst}")
                        print(Fore.MAGENTA + f"Request URI: {packet.http.request_uri}")
                        print(Fore.MAGENTA + f"Request: {packet.http.request_method} {packet.http.host}{packet.http.request_uri}")
                        
                        # Extract form data (username, password, etc.)
                        if hasattr(packet.http, 'file_data'):
                            print(Fore.MAGENTA + f"Form Data: {packet.http.file_data}")
                        else:
                            print(Fore.RED + "No form data found in POST request.")
            except AttributeError as e:
                print(Fore.RED + f"Packet error: {e}")
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

if __name__ == "__main__":
    main()
