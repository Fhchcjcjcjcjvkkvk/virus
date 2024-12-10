import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile
import pyshark
import asyncio

# Function to get authentication details from netsh using ESSID
def get_authentication(essid):
    command = 'netsh wlan show networks mode=bssid'
    result = os.popen(command).read()
    lines = result.split("\n")
    current_ssid = None

    for line in lines:
        line = line.strip()
        if line.startswith("SSID ") and essid in line:
            current_ssid = essid
        elif "Authentication" in line and current_ssid == essid:
            return line.split(":")[1].strip()
    return "Unknown"

# Function to scan WiFi networks
def scan_wifi():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Assuming the first interface
    iface.scan()
    time.sleep(2)  # Wait for scan results to populate
    networks = iface.scan_results()
    return networks

# Function to capture beacon frames using PyShark
def capture_beacons(interface, capture_duration=10):
    beacon_count = {}

    # Set up a new event loop (important to avoid asyncio errors)
    asyncio.set_event_loop(asyncio.new_event_loop())

    # Start capturing packets for beacon frames (management frames with subtype 'beacon')
    capture = pyshark.LiveCapture(interface=interface, bpf_filter="type mgt subtype beacon")
    print(f"Capturing beacon packets on {interface}...")
    
    # Capture packets for the specified duration and count the beacons
    for packet in capture.sniff_continuously(packet_count=capture_duration * 10):  # Capture for about 'capture_duration' seconds
        if hasattr(packet, 'wlan'):
            essid = packet.wlan.ssid if hasattr(packet.wlan, 'ssid') else "Unknown"
            if essid not in beacon_count:
                beacon_count[essid] = 0
            beacon_count[essid] += 1

    return beacon_count

# Function to display the network details and live beacon count
def live_scan():
    # Set up Wi-Fi interface for capturing packets in monitor mode (ensure this is supported on your device)
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Get the first interface

    # Correct interface name for PyShark (you provided "WiFi 2")
    iface_name = "WiFi"  # Use the exact interface name you provided

    while True:
        networks = scan_wifi()  # Perform the WiFi scan
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30} {'Beacons':<10}")
        print("-" * 110)

        # Capture beacon packets for 5 seconds
        beacon_counts = capture_beacons(iface_name, capture_duration=5)

        for network in networks:
            bssid = network.bssid
            essid = network.ssid
            signal = network.signal
            auth = get_authentication(essid)
            beacons = beacon_counts.get(essid, 0)

            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30} {beacons:<10}")

        time.sleep(5)  # Wait for 5 seconds before the next scan

if __name__ == "__main__":
    live_scan()
