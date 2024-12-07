import pyshark
import sys

# Function to handle packet processing
def packet_handler(packet):
    try:
        if 'wlan' in packet:
            # Extracting BSSID, ESSID, and channel from beacon frames (Type: Beacon)
            if 'wlan_mgt' in packet:
                # Beacon frame or probe request frame
                bssid = packet.wlan.bssid
                ssid = packet.wlan.ssid if hasattr(packet.wlan, 'ssid') else 'N/A'
                channel = packet.wlan_radio.channel if hasattr(packet.wlan_radio, 'channel') else 'N/A'
                signal_strength = packet.dbm_antsignal if hasattr(packet, 'dbm_antsignal') else 'N/A'
                encryption = packet.wlan.encryption if hasattr(packet.wlan, 'encryption') else 'None'
                cipher = packet.wlan.cipher if hasattr(packet.wlan, 'cipher') else 'N/A'
                print(f"BSSID: {bssid}\tESSID: {ssid}\tCH: {channel}\tENC: {encryption}\tCIPHER: {cipher}\tSignal: {signal_strength} dBm")

            # WPA handshake detection (looking for 4-way handshake packets)
            if 'eapol' in packet:
                print(f"WPA Handshake detected for BSSID: {packet.wlan.bssid}")
                
    except AttributeError:
        pass

# Function to start packet capture and process them
def start_capture(interface):
    print(f"Sniffing on {interface}...\n")
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='wlan')
    capture.apply_on_packets(packet_handler)

def main():
    if len(sys.argv) != 3:
        print("Usage: python airhunter.py <interface>")
        sys.exit(1)

    interface = sys.argv[2]
    start_capture(interface)

if __name__ == "__main__":
    main()
