import pyshark
import argparse
from colorama import init, Fore

def main():
    # Initialize colorama for colored output
    init(autoreset=True)

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Capture DNS packets and HTTP login requests.")
    parser.add_argument("-i", "--interface", required=True, help="The network interface to sniff on.")
    args = parser.parse_args()

    # Start live capture on the specified interface with filter for HTTP and DNS
    try:
        print(f"Starting capture on interface: {args.interface}")
        capture = pyshark.LiveCapture(interface=args.interface, display_filter="http or dns")

        # Process each packet
        for packet in capture.sniff_continuously():
            try:
                # Debugging: Show each HTTP request captured
                if 'http' in packet:
                    print("\n--- HTTP Packet Captured ---")
                    print(Fore.YELLOW + f"Request Method: {packet.http.request_method}")
                    print(Fore.YELLOW + f"Request URI: {packet.http.request_uri}")
                    print(Fore.YELLOW + f"Host: {packet.http.host}")
                    print(Fore.YELLOW + f"Source: {packet.ip.src} -> Destination: {packet.ip.dst}")

                    # Check if the HTTP packet is a POST to a login page
                    if packet.http.request_method == "POST" and '/login' in packet.http.request_uri:
                        print("\n--- HTTP Login Request Captured ---")
                        print(Fore.MAGENTA + f"Source: {packet.ip.src} -> Destination: {packet.ip.dst}")
                        print(Fore.MAGENTA + f"Request URI: {packet.http.request_uri}")
                        print(Fore.MAGENTA + f"Request: {packet.http.request_method} {packet.http.host}{packet.http.request_uri}")
                        
                        # Extract form data (username, password, etc.)
                        if hasattr(packet.http, 'file_data'):
                            print(Fore.MAGENTA + f"Form Data: {packet.http.file_data}")
                        else:
                            print(Fore.RED + "No form data found in POST request.")

                # Check if the packet contains DNS layer
                elif 'dns' in packet:
                    print("\n--- DNS Packet Captured ---")
                    # Show DNS query details (querying domain name)
                    if hasattr(packet.dns, 'qry_name'):
                        print(Fore.CYAN + f"DNS Query: {packet.dns.qry_name}")
                    # Show DNS response details (answered domain name)
                    elif hasattr(packet.dns, 'ans_name'):
                        print(Fore.CYAN + f"DNS Response: {packet.dns.ans_name}")

            except AttributeError as e:
                print(Fore.RED + f"Packet error: {e}")
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

if __name__ == "__main__":
    main()
