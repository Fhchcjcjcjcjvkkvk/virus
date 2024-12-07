from scapy.all import *
import time

def packet_handler(packet):
    if packet.haslayer(Dot11Beacon):  # Check if it's a beacon frame
        ssid = packet[Dot11Elt].info.decode()  # SSID of the network
        bssid = packet[Dot11].addr2  # BSSID (MAC address of AP)
        rssi = packet.dBm_AntSignal  # Signal strength (RSSI)
        beacon_period = packet[Dot11Beacon].beaconinterval  # Beacon period in time units

        print(f"SSID: {ssid}")
        print(f"BSSID: {bssid}")
        print(f"RSSI: {rssi} dBm")
        print(f"Beacon Period: {beacon_period} (time units)")
        print("-" * 40)

def scan_networks():
    print("Starting network scan...")
    sniff(prn=packet_handler, iface="Wi-Fi", count=100, timeout=10)

if __name__ == "__main__":
    scan_networks()
