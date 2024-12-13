from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, RadioTap

# To hold the discovered stations and APs
associated_stations = {}

# Define a function to process the packets
def packet_handler(packet):
    if packet.haslayer(Dot11):
        # Capture beacon frames (APs broadcasting their information)
        if packet.type == 0 and packet.subtype == 8:  # Beacon frame
            bssid = packet[Dot11].addr3  # BSSID (AP's MAC address)
            ssid = packet[Dot11Beacon].info.decode(errors="ignore")  # SSID
            print(f"AP found: BSSID={bssid} SSID={ssid}")
        
        # Capture probe request frames (stations searching for APs)
        elif packet.type == 0 and packet.subtype == 4:  # Probe Request frame
            station_mac = packet[Dot11].addr2  # Source MAC address (station searching)
            print(f"Station searching: MAC={station_mac} (not associated)")

        # Capture probe response frames (APs responding to probe requests)
        elif packet.type == 0 and packet.subtype == 5:  # Probe Response frame
            bssid = packet[Dot11].addr3  # BSSID (AP's MAC address)
            ssid = packet[Dot11Beacon].info.decode(errors="ignore")  # SSID
            print(f"Probe response: BSSID={bssid} SSID={ssid}")
            
        # Handle association frames (show stations associated with APs)
        elif packet.type == 1 and packet.subtype == 0:  # Association Request frame
            station_mac = packet[Dot11].addr2  # Source MAC address (station trying to associate)
            bssid = packet[Dot11].addr3  # BSSID (AP's MAC address)
            associated_stations[station_mac] = bssid  # Track association
            print(f"Station associated: MAC={station_mac} BSSID={bssid}")

        elif packet.type == 1 and packet.subtype == 1:  # Association Response frame
            station_mac = packet[Dot11].addr2  # Source MAC address (station)
            bssid = packet[Dot11].addr3  # BSSID (AP's MAC address)
            if station_mac in associated_stations:
                print(f"Station {station_mac} confirmed associated with AP {bssid}")

# Start sniffing on the wireless interface (monitor mode required)
def start_sniffing(interface="wlan0"):
    print(f"Sniffing on {interface}...")
    sniff(iface=interface, prn=packet_handler, store=0)

# Run the script
if __name__ == "__main__":
    # Replace 'wlan0' with your network interface in monitor mode (on Windows, this might be 'Wi-Fi')
    start_sniffing(interface="WiFi")
