import argparse
from scapy.all import sniff, Dot11
from prettytable import PrettyTable

def capture_packets(interface, beacon_count):
    """
    Sniffs packets on the specified interface and displays beacon information in a table format.

    :param interface: The interface to capture packets from.
    :param beacon_count: Number of beacon frames to capture before stopping.
    """
    beacon_stats = {}
    total_beacons = 0

    def packet_handler(packet):
        nonlocal total_beacons
        # Check if the packet has a Dot11 layer and is a beacon frame
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
            bssid = packet.addr2
            ssid = packet.info.decode(errors='ignore') if packet.info else "<Hidden SSID>"

            if bssid not in beacon_stats:
                beacon_stats[bssid] = {
                    'SSID': ssid,
                    'Beacons': 0,
                    'Data': 0
                }

            # Increment the beacon count
            beacon_stats[bssid]['Beacons'] += 1
            total_beacons += 1

            print(f"Beacon {total_beacons}: BSSID={bssid}, SSID={ssid}")

        # Check if the packet is a data packet
        if packet.haslayer(Dot11) and packet.type == 2:
            bssid = packet.addr2
            if bssid in beacon_stats:
                beacon_stats[bssid]['Data'] += 1

        # Stop sniffing when the target beacon count is reached
        if total_beacons >= beacon_count:
            return True

    print(f"Starting sniffing on {interface}. Waiting for {beacon_count} beacon frames...")

    try:
        sniff(iface=interface, prn=packet_handler, stop_filter=lambda x: total_beacons >= beacon_count)
    except PermissionError:
        print("Error: Insufficient permissions. Please run this script as Administrator.")
    except Exception as e:
        print(f"An error occurred: {e}")

    # Display the results in a table
    table = PrettyTable()
    table.field_names = ["BSSID", "SSID", "Beacons", "Data"]
    for bssid, stats in beacon_stats.items():
        table.add_row([bssid, stats['SSID'], stats['Beacons'], stats['Data']])

    print(table)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture Wi-Fi beacon frames and display network statistics.")
    parser.add_argument("interface", help="The name of the network interface to use for sniffing.")
    parser.add_argument("--count-beacons", type=int, default=10, help="The number of beacon frames to capture (default: 10).")

    args = parser.parse_args()

    capture_packets(args.interface, args.count_beacons)
