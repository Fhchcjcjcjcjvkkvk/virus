import argparse
import time
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt

def process_packet(packet, network_info):
    """Process each packet to extract BSSID, client MACs, Beacon count, and Channel."""
    if packet.haslayer(Dot11):
        bssid = packet[Dot11].addr3  # Extract BSSID (Access Point)
        if bssid:
            # Initialize network info if not already present
            if bssid not in network_info:
                network_info[bssid] = {
                    'beacons': 0,  # Count of Beacon frames
                    'clients': set(),  # Set of client MAC addresses
                    'essid': 'Unknown',  # Default ESSID
                    'channel': None,  # Channel information
                }

            # Check if it's a Beacon frame and update the Beacon count
            if packet.haslayer(Dot11Beacon):
                network_info[bssid]['beacons'] += 1
                if packet.haslayer(Dot11Elt):
                    # Extract ESSID if available
                    if packet[Dot11Elt].ID == 0:
                        network_info[bssid]['essid'] = packet[Dot11Elt].info.decode(errors='ignore')
                    # Extract channel (ID 3 is DS Parameter Set)
                    if packet[Dot11Elt].ID == 3:
                        network_info[bssid]['channel'] = packet[Dot11Elt].info[0]

            # Check if it's a Data frame (optional, for clients)
            if packet.haslayer(Dot11) and packet[Dot11].type == 2:  # type == 2 is Data frame
                client_mac = packet[Dot11].addr2  # Source address of the data packet
                if client_mac and client_mac != bssid:  # Avoid adding the BSSID as a client
                    network_info[bssid]['clients'].add(client_mac)

def process_pcap_file(pcap_file, duration=30):
    """Process the .pcap file for the specified duration and return network info."""
    network_info = {}
    start_time = time.time()

    # Read the pcap file and process packets
    packets = rdpcap(pcap_file)
    for packet in packets:
        if time.time() - start_time > duration:
            break  # Stop processing after the specified duration
        process_packet(packet, network_info)

    return network_info

def display_networks(network_info):
    """Display the networks (BSSIDs) with Beacon count, ESSID, and Channel."""
    print("NUM.  ESSID                BSSID               Beacons   Channel")
    print("-" * 60)
    for idx, (bssid, info) in enumerate(network_info.items(), 1):
        # Handle cases where the channel might be None (not found in the beacon)
        channel = info['channel'] if info['channel'] is not None else 'Unknown'
        print(f"{idx}. {info['essid'][:20]:<20} {bssid}  {info['beacons']}      {channel}")

def display_clients(network_info, selected_bssid):
    """Display the client MAC addresses for a selected BSSID."""
    clients = network_info[selected_bssid]['clients']
    if clients:
        print(f"\nClients connected to {selected_bssid}:")
        for client in clients:
            print(f"  - {client}")
    else:
        print(f"No clients found for BSSID {selected_bssid}.")

def main():
    # Step 1: Get the path to the pcap file
    pcap_file = input("Enter path to the pcap file: ").strip()

    # Step 2: Process the pcap file for 30 seconds
    print("Calculating for 30 seconds...")
    network_info = process_pcap_file(pcap_file, duration=30)

    # Step 3: Display networks with Beacon counts and Channel info
    display_networks(network_info)

    # Step 4: Select a network by number
    try:
        selected_num = int(input("\nSelect network by number: ").strip())
        selected_bssid = list(network_info.keys())[selected_num - 1]

        # Step 5: Display clients for the selected BSSID
        display_clients(network_info, selected_bssid)

    except (ValueError, IndexError):
        print("Invalid selection.")

if __name__ == "__main__":
    main()
