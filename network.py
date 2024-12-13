import pyshark
import argparse
from colorama import init, Fore

def main():
    # Initialize colorama for colored output
    init(autoreset=True)

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="A simple network sniffer to capture both HTTP and DNS traffic.")
    parser.add_argument("-i", "--interface", required=True, help="The network interface to sniff on.")
    args = parser.parse_args()

    # Start live capture on the specified interface with filter for HTTP and DNS
    try:
        print(f"Starting capture on interface: {args.interface}")
        capture = pyshark.LiveCapture(interface=args.interface, display_filter="http or dns")

        # Process each packet
        for packet in capture.sniff_continuously():
            try:
                # Ensure the packet has an IP layer before accessing packet.ip
                if hasattr(packet, 'ip'):
                    # Check if the packet contains HTTP layer
                    if 'http' in packet:
                        # If it's a POST request (usually for form submissions)
                        if packet.http.request_method == "POST":
                            print("\n--- POST Data Captured (HTTP) ---")
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
                        print("\n--- DNS Query/Response Captured ---")
                        print(Fore.CYAN + f"Source: {packet.ip.src} -> Destination: {packet.ip.dst}")
                        
                        # Print DNS query or response details
                        if hasattr(packet.dns, 'qry_name'):  # DNS query
                            print(Fore.CYAN + f"DNS Query: {packet.dns.qry_name}")
                        elif hasattr(packet.dns, 'ans_name'):  # DNS response
                            print(Fore.CYAN + f"DNS Response: {packet.dns.ans_name}")
                        else:
                            print(Fore.RED + "Unknown DNS packet format.")
                else:
                    print(Fore.YELLOW + "Packet does not have an IP layer. Skipping packet.")
            except AttributeError as e:
                print(Fore.RED + f"Packet error: {e}")
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

if __name__ == "__main__":
    main()
