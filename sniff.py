import pyshark
import argparse

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="A simple network sniffer to display HTTP packets and network usage.")
    parser.add_argument("-i", "--interface", required=True, help="The network interface to sniff on.")
    args = parser.parse_args()

    # Start live capture on the specified interface
    try:
        print(f"Starting capture on interface: {args.interface}")
        capture = pyshark.LiveCapture(interface=args.interface, display_filter="http")

        # Process each packet
        for packet in capture.sniff_continuously():
            try:
                print("\n--- HTTP Packet ---")
                if 'http' in packet:
                    print(f"Source: {packet.ip.src} -> Destination: {packet.ip.dst}")
                    print(f"Request: {packet.http.request_method} {packet.http.host}{packet.http.request_uri}")
                    print(f"User-Agent: {packet.http.get('User-Agent', 'N/A')}")

                    # Extract and display form data for POST requests
                    if packet.http.request_method == "POST":
                        if hasattr(packet.http, 'file_data'):
                            print(f"Form Data: {packet.http.file_data}")
                        else:
                            print("No form data found in POST request.")
                    
                    print(f"Raw Packet Data: {packet.get('highest_layer', 'N/A')}\n{packet}")
                else:
                    print("Non-HTTP packet captured.")
            except AttributeError as e:
                print(f"Packet error: {e}")
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
