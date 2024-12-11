import pyshark
import sys
import time

# Set global variables
BSSID = None
WPA_HANDSHAKE = False

def packet_callback(pkt):
    global WPA_HANDSHAKE, BSSID
    
    # Capture Beacon Frames (AP broadcasts)
    if 'wlan' in pkt:
        if pkt.wlan.fc_type_subtype == '0x08':  # Beacon frame
            ap_bssid = pkt.wlan.bssid
            ap_ssid = pkt.wlan.ssid if 'ssid' in pkt.wlan.field_names else "Hidden"
            print(f"Beacon frame from AP: {ap_ssid} ({ap_bssid})")
    
    # Capture EAPOL frames (WPA handshake)
    if 'eapol' in pkt:
        if pkt.wlan.bssid == BSSID:
            print(f"EAPOL frame detected from AP: {BSSID}")
            if not WPA_HANDSHAKE:
                print("Possible WPA Handshake found!")
                WPA_HANDSHAKE = True
                print(f"WPA Handshake: {BSSID}")
    
    # Detect client reconnects
    if 'wlan' in pkt:
        if pkt.wlan.fc_type_subtype == '0x00':  # Data frame
            client_mac = pkt.wlan.sa
            print(f"Client {client_mac} detected reconnecting to AP: {BSSID}")

def start_capture(interface, bssid, output_file):
    global BSSID
    BSSID = bssid

    print(f"Starting packet capture on interface: {interface}, looking for BSSID: {bssid}")
    
    # Start the capture
    capture = pyshark.LiveCapture(interface=interface, display_filter="wlan.fc.type_subtype == 0x08 or eapol")
    capture.apply_on_packets(packet_callback)

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python airsniff.py -w capture.pcap -a <BSSID> <interface>")
        sys.exit(1)

    # Parse arguments
    output_file = sys.argv[2]
    bssid = sys.argv[4]
    interface = sys.argv[5]

    # Start the capture process
    start_capture(interface, bssid, output_file)
