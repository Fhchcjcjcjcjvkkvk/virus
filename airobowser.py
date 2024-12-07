import pyshark

# Function to capture beacon frames from a pcap file
def capture_beacon_frames(pcap_file):
    # Create a capture object for the pcap file
    capture = pyshark.FileCapture(pcap_file, display_filter="wlan.fc.type_subtype == 8")

    # Display the details of each captured beacon frame
    print(f"{'BSSID':<20} {'ESSID':<30} {'PWR':<6} {'CH':<4} {'ENC':<10} {'CIPHER':<6}")
    
    for packet in capture:
        if hasattr(packet, "wlan"):
            bssid = packet.wlan.bssid
            essid = packet.wlan.ssid
            # Get signal strength from the radiotap header, if available
            try:
                power = packet.radiotap.dbm_antsignal
            except AttributeError:
                power = "N/A"
            
            # Try to capture the channel and encryption type from the beacon frame
            channel = packet.wlan_radio.channel if hasattr(packet, "wlan_radio") else "N/A"
            encryption = packet.wlan.wep_id if hasattr(packet.wlan, "wep_id") else "Unknown"
            
            # Print the captured data
            print(f"{bssid:<20} {essid:<30} {power:<6} {channel:<4} {encryption:<10} {'N/A':<6}")

# Main function
if __name__ == "__main__":
    pcap_file = r"C:\devil\cap.pcap"  # Correct file path to your PCAP
    capture_beacon_frames(pcap_file)
