import scapy.all as scapy
import sys
import os

# Function to handle packet processing from .pcap file and calculate stats
def analyze_pcap(pcap_file):
    packets = scapy.rdpcap(pcap_file)  # Read all packets from the .pcap file

    bssids = {}  # Dictionary to store BSSID details (ESSID, Encryption, Beacons)
    data_count = {}  # Dictionary to store data packet counts for each BSSID
    eapol_count = {}  # Dictionary to store EAPOL packet counts for each BSSID
    eapol_packets = []  # List to store EAPOL packets (handshakes)
    all_packets = []  # List to store all packets (for cap file)

    # Iterate through the packets and calculate relevant statistics
    for packet in packets:
        if packet.haslayer(scapy.Dot11):
            # Extract BSSID (Access Point MAC address)
            bssid = packet[scapy.Dot11].addr2

            if packet.haslayer(scapy.Dot11Beacon):
                # Beacon frame (access point)
                essid = packet[scapy.Dot11Elt].info.decode() if packet.haslayer(scapy.Dot11Elt) else "Unknown"
                encryption = get_encryption(packet)
                
                # Store BSSID details
                if bssid not in bssids:
                    bssids[bssid] = {'ESSID': essid, 'Encryption': encryption, 'Beacons': 1}
                else:
                    bssids[bssid]['Beacons'] += 1

                # Add beacon frame to all_packets
                all_packets.append(packet)

            elif packet.haslayer(scapy.EAPOL):
                # EAPOL frame (WPA/WPA2 handshake)
                eapol_packets.append(packet)  # Store the EAPOL packet
                if bssid not in eapol_count:
                    eapol_count[bssid] = 1
                else:
                    eapol_count[bssid] += 1

                # Add EAPOL frame to all_packets
                all_packets.append(packet)

            # Count data packets (not EAPOL or Beacon)
            if packet.haslayer(scapy.IP) or packet.haslayer(scapy.UDP):
                if bssid not in data_count:
                    data_count[bssid] = 1
                else:
                    data_count[bssid] += 1

                # Add data packet to all_packets
                all_packets.append(packet)

    # Print results in a readable format
    print("\n BSSID                Beacons    #Data  ENC     ESSID              EAPOL")
    print(" --------------------------------------------------------------------------------")
    for bssid in bssids:
        beacons = bssids[bssid]['Beacons']
        data = data_count.get(bssid, 0)
        encryption = bssids[bssid]['Encryption']
        essid = bssids[bssid]['ESSID']
        eapol = eapol_count.get(bssid, 0)
        
        print(f" {bssid}  {beacons:<9} {data:<6} {encryption:<6} {essid:<18} {eapol}")
    
    # Save all packets (beacons, data, EAPOL) to a .cap file
    if len(all_packets) > 0:
        output_cap_file = get_output_filename(pcap_file)  # Generate output filename based on input
        scapy.wrpcap(output_cap_file, all_packets)  # Save all relevant packets to .cap file
        print(f"\n[INFO] All relevant packets (beacons, data, EAPOL) saved as {output_cap_file}")
    else:
        print("\n[INFO] No relevant packets found (no beacons, data, or EAPOL packets).")

# Helper function to determine the encryption type from the beacon frame
def get_encryption(packet):
    if packet.haslayer(scapy.Dot11Beacon):
        cap = packet[scapy.Dot11Beacon].cap
        if cap & 0x0040:  # WEP encryption
            return "WEP"
        elif cap & 0x0010:  # WPA/WPA2 encryption
            return "WPA/WPA2"
        else:
            return "None"
    return "None"

# Function to get the output filename by changing the extension from .pcap to .cap
def get_output_filename(pcap_file):
    # Change the extension from .pcap to .cap
    output_filename = os.path.splitext(pcap_file)[0] + ".cap"
    return output_filename

# Main function to execute the analysis from the .pcap file
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python airsniff.py <handshake.pcap>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    
    try:
        print(f"[INFO] Analyzing pcap file: {pcap_file}")
        analyze_pcap(pcap_file)  # Process and analyze the .pcap file
    except Exception as e:
        print(f"Error processing the pcap file: {e}")
        sys.exit(1)
