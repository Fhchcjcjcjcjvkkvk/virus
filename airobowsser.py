import pyshark

# Function to process packets and extract relevant details
def process_packet(pkt):
    try:
        if 'wlan' in pkt:
            bssid = pkt.wlan.bssid
            if hasattr(pkt, 'wlan_mgt'):
                if hasattr(pkt.wlan_mgt, 'ssid'):
                    ssid = pkt.wlan_mgt.ssid
                else:
                    ssid = "N/A"
            else:
                ssid = "N/A"

            # Extract WPA handshake
            if hasattr(pkt, 'wlan_eapol'):
                if pkt.wlan_eapol.eapol_type == '1':  # WPA Handshake
                    print(f'WPA Handshake detected for BSSID: {bssid}')

            # Check encryption and authentication methods
            if hasattr(pkt, 'wlan_wep'):
                encryption = "WEP"
                cipher = "WEP"
                auth = "Open"
            elif hasattr(pkt, 'wlan_rsn'):
                encryption = "WPA/WPA2"
                cipher = "TKIP"  # Or AES depending on the packet
                auth = "PSK"  # Assuming PSK based on the example
            else:
                encryption = "Unknown"
                cipher = "Unknown"
                auth = "Unknown"

            # Display BSSID, SSID, Encryption info
            print(f'BSSID: {bssid}  SSID: {ssid}  ENC: {encryption}  CIPHER: {cipher}  AUTH: {auth}')
    except AttributeError as e:
        pass

# Function to capture packets and display the output
def capture_wifi_packets(interface="Wi-Fi"):
    print(f"Starting WiFi packet capture on {interface}...")
    cap = pyshark.LiveCapture(interface=interface)

    for pkt in cap.sniff_continuously():
        process_packet(pkt)

if __name__ == "__main__":
    capture_wifi_packets("WiFi")  # Adjust interface name if needed
