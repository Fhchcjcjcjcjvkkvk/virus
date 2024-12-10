import pyshark
import argparse
import time
import sys

# Function to display the banner in red
def display_banner():
    # ANSI escape code for red color
    red_color = '\033[91m'
    reset_color = '\033[0m'
    
    banner = f"""
    {red_color}.               .     
    .´  ·  .     .  ·  `.  
     :  :  :  (¯)  :  :  : 
     `.  ·  ` /¯\\ ´  ·  .´  
       `     /¯¯¯\\     ´   

    Capturing WPA Handshake...{reset_color}
    """
    print(banner)

def capture_traffic(interface, bssid, output_file, timeout=120):
    # Build display filter for EAPOL frames from the specific BSSID
    display_filter = f"wlan.bssid == {bssid} and eapol"

    # Start capture with the specified interface and filter
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=display_filter, output_file=output_file)

    start_time = time.time()
    found_handshake = False

    # Start capturing traffic
    print("Capturing traffic... Press Ctrl+C to stop.")
    
    try:
        for packet in capture.sniff_continuously():
            if time.time() - start_time > timeout:
                print("NO HANDSHAKE! Timeout reached.")
                break
            if 'eapol' in packet:
                print("[ WPA HANDSHAKE FOUND ! ]")
                found_handshake = True
                break
    except KeyboardInterrupt:
        print("\nQuitting...")  # Gracefully handle Ctrl+C
    
    # Close capture after processing (this ensures the pcap file is saved)
    capture.close()

    # If handshake was not found within timeout
    if not found_handshake:
        print("NO HANDSHAKE! Timeout reached.")
    else:
        print("[ WPA HANDSHAKE CAPTURED ]")

if __name__ == "__main__":
    # Display the banner
    display_banner()

    # Command-line arguments parsing
    parser = argparse.ArgumentParser(description="Capture traffic and detect WPA handshake.")
    parser.add_argument('-w', '--write', required=True, help="Output file to write the pcap data.")
    parser.add_argument('-a', '--ap', required=True, help="The AP MAC address (BSSID) to capture traffic from.")
    parser.add_argument('-i', '--interface', required=True, help="The network interface to capture traffic on.")
    args = parser.parse_args()

    # Run the capture function
    capture_traffic(args.interface, args.ap, args.write)
