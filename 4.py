import pyshark

# Dictionary to hold the Access Points (BSSIDs) and their Beacon count
ap_beacons = {}

def packet_handler(pkt):
    if 'wlan' in pkt:
        if pkt.wlan.fc_type_subtype == '0x08':  # Beacon frame subtype
            bssid = pkt.wlan.bssid  # AP's MAC address (BSSID)
            ssid = pkt.wlan.ssid if 'ssid' in pkt.wlan.field_names else "(Hidden SSID)"
            
            # Update the beacon count for this AP
            if bssid not in ap_beacons:
                ap_beacons[bssid] = {"ssid": ssid, "beacon_count": 0}
            
            ap_beacons[bssid]["beacon_count"] += 1

            # Print the information about this Beacon
            print(f"SSID: {ssid}, BSSID: {bssid}, Beacon Count: {ap_beacons[bssid]['beacon_count']}")

# Start sniffing on the available network interface
def start_sniffing(interface="Wi-Fi"):
    print(f"Sniffing on interface: {interface}. Press Ctrl+C to stop.")
    capture = pyshark.LiveCapture(interface=interface, display_filter="wlan.fc.type_subtype == 0x08")
    capture.apply_on_packets(packet_handler)

if __name__ == "__main__":
    try:
        start_sniffing("WiFi")  # Replace with your actual Wi-Fi interface name if needed
    except KeyboardInterrupt:
        print("\nSniffing stopped.")
