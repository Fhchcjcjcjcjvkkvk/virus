import pyshark

def capture_wifi_packets(interface):
    capture = pyshark.LiveCapture(interface=interface, bpf_filter="wlan")
    
    print(f"Capturing packets on {interface}...")
    for packet in capture.sniff_continuously():
        if hasattr(packet, 'wlan'):
            wlan = packet.wlan
            
            # Check for WPA handshake
            if hasattr(wlan, 'key_info') and wlan.key_info == '0x0080':
                print(f"\n[ WPA Handshake Detected ]")
                print(f"Time: {packet.sniff_time.strftime('%Y-%m-%d %H:%M')}")
                print(f"BSSID: {wlan.bssid}")
                print(f"Source MAC: {wlan.ta}")
                print(f"Destination MAC: {wlan.ra}")
            
            # Access Point Information (AP)
            if hasattr(wlan, 'ssid'):
                print(f"\nBSSID: {wlan.bssid}   ESSID: {wlan.ssid}")
                print(f"Encryption: {wlan.encryption}")
                print(f"Cipher: {wlan.cipher}")
                print(f"Authentication: {wlan.authentication}")
                
            # Display the station information (associated clients)
            if hasattr(wlan, 'sta'):
                print(f"Station: {wlan.sta}  Signal Power: {wlan.signal_strength}")

if __name__ == '__main__':
    interface = input("Enter your network interface (e.g., wlan0): ")
    capture_wifi_packets(interface)
