import pyshark

# Function to display network information from capture
def display_wifi_info(packet):
    # Filter out packets with WLAN (Wi-Fi) protocol
    if 'wlan' in packet:
        try:
            # Extract necessary information from the packet
            bssid = packet.wlan.bssid
            channel = packet.wlan_channel if 'wlan_channel' in packet else 'N/A'
            signal_strength = packet.wlan_signal_strength if 'wlan_signal_strength' in packet else 'N/A'
            enc = packet.wlan.encryption if 'wlan.encryption' in packet else 'N/A'
            cipher = packet.wlan.cipher if 'wlan.cipher' in packet else 'N/A'
            essid = packet.wlan.ssid if 'wlan.ssid' in packet else 'N/A'
            
            # Print packet details (you can format this as needed)
            print(f"BSSID: {bssid}, Channel: {channel}, Signal Strength: {signal_strength}, "
                  f"Encryption: {enc}, Cipher: {cipher}, ESSID: {essid}")
        except AttributeError as e:
            pass

# List available interfaces
def list_interfaces():
    interfaces = pyshark.LiveCapture.interfaces()
    for i, interface in enumerate(interfaces):
        print(f"{i}: {interface}")

# Select interface (manual choice)
interface_idx = int(input("Enter the index of the interface to capture on: "))
interface = pyshark.LiveCapture.interfaces()[interface_idx]

# Start capturing packets on the selected interface
capture = pyshark.LiveCapture(interface=interface, display_filter="wlan")

# Loop through captured packets and process them
for packet in capture.sniff_continuously():
    display_wifi_info(packet)
