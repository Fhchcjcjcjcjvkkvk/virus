import pyshark
import sys

def list_interfaces():
    # List all interfaces available on the system using pyshark.LiveCapture.get_interfaces
    interfaces = pyshark.LiveCapture.get_interfaces()
    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}: {iface}")
    return interfaces

def capture_http_requests(interface):
    # Set up the capture on the specified interface
    capture = pyshark.LiveCapture(interface=interface, display_filter='http.request')

    print(f"Starting packet capture on interface {interface}...\n")
    try:
        # Iterate through the captured packets
        for packet in capture.sniff_continuously():
            if 'HTTP' in packet:
                print("---- HTTP Request ----")
                print(f"Timestamp: {packet.sniff_time}")
                print(f"Source IP: {packet.ip.src}")
                print(f"Destination IP: {packet.ip.dst}")
                print(f"HTTP Method: {packet.http.request_method}")
                print(f"Host: {packet.http.host}")
                print(f"Request URI: {packet.http.request_uri}")
                print(f"Raw HTTP Data: {packet.http.get_raw() if hasattr(packet.http, 'get_raw') else 'No raw HTTP content'}")
                print("------------------------")
    except KeyboardInterrupt:
        print("\nCapture interrupted. Exiting...")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # First, list the available interfaces
    interfaces = list_interfaces()

    # Get the interface from command line arguments
    if len(sys.argv) != 3 or sys.argv[1] != "-i":
        print("Usage: python airbridge.py -i <interface_number>")
        sys.exit(1)

    try:
        interface_num = int(sys.argv[2]) - 1  # Convert to 0-based index
        interface = interfaces[interface_num]  # Get the interface by number
        print(f"Using interface: {interface}")
        capture_http_requests(interface)
    except (IndexError, ValueError):
        print("Invalid interface number. Please provide a valid interface from the list.")
        sys.exit(1)
