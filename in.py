import pyshark
import sys
import time

def capture_eapol(interface, channel, output_file):
    """
    Capture EAPOL packets using PyShark from a given interface and channel.
    Saves the packets to a .pcap file.
    """
    print(f"Starting capture on interface {interface}...")
    
    # Use TShark (which is part of Wireshark) to capture packets on the specified interface
    capture = pyshark.LiveCapture(interface=interface, display_filter="eapol")
    
    # Setting the capture duration to 60 seconds (you can adjust as needed)
    capture.sniff(timeout=60)

    # Check if EAPOL packets are captured
    eapol_packets = [pkt for pkt in capture if 'EAPOL' in pkt]
    if eapol_packets:
        print(f"Captured {len(eapol_packets)} EAPOL packets.")
        # Write packets to a .pcap file
        capture.dump_packets(output_file)
        print(f"Saved captured packets to {output_file}")
    else:
        print("No EAPOL packets captured.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python capture_eapol.py <interface> <channel> <output_file>")
        sys.exit(1)

    interface = sys.argv[1]  # Interface to capture packets on (e.g., 'Wi-Fi')
    channel = sys.argv[2]    # Channel to monitor (though TShark on Windows doesn't allow easy channel setting)
    output_file = sys.argv[3]  # Output file to save the .pcap data

    capture_eapol(interface, channel, output_file)
