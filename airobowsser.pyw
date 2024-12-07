import pyshark
import sys
import time

def capture_packets(interface, ap_mac):
    # Initialize the packet capture on the given interface
    capture = pyshark.LiveCapture(interface=interface, display_filter='wlan.fc.type_subtype == 0x08')

    print("Starting packet capture... Press Ctrl+C to stop.")
    print("Timestamp           | BSSID             | ESSID       | Channel | Encryption | CIPHER | AUTH | STATION MAC")

    try:
        for packet in capture.sniff_continuously():
            # Process only beacon or association packets
            if hasattr(packet, 'wlan') and hasattr(packet.wlan, 'addr2'):
                bssid = packet.wlan.addr2
                essid = packet.wlan.ssid if hasattr(packet.wlan, 'ssid') else "N/A"
                channel = packet.wlan_radio.channel if hasattr(packet, 'wlan_radio') else "N/A"
                encryption = "WPA" if hasattr(packet.wlan, 'encryption') else "OPEN"
                cipher = packet.wlan.encryption if hasattr(packet.wlan, 'encryption') else "N/A"
                auth = packet.wlan.auth_alg if hasattr(packet.wlan, 'auth_alg') else "N/A"
                
                print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {bssid} | {essid} | {channel} | {encryption} | {cipher} | {auth} |")
                
                # Capture WPA handshake
                if 'WPA Handshake' in str(packet):
                    print(f"  WPA handshake detected: {bssid}")
                
                # Track associated stations
                if hasattr(packet, 'wlan') and packet.wlan.addr1 != ap_mac:
                    station_mac = packet.wlan.addr1
                    print(f"  Associated Station: {station_mac}")
                
                # Add more processing as needed
                
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python airhunter.py -a <AP_MAC> <interface>")
        sys.exit(1)

    action = sys.argv[1]
    ap_mac = sys.argv[2]
    interface = sys.argv[3]

    if action == '-a':
        capture_packets(interface, ap_mac)
    else:
        print("Invalid action. Use '-a' to start packet capture.")
