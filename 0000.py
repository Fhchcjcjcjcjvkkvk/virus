import tkinter as tk
from scapy.all import *
from collections import defaultdict
import threading

# Dictionary to hold information about networks and the number of beacons
network_data = defaultdict(lambda: {'beacons': 0, 'essid': None})

# Function to handle sniffing and extracting beacon packets
def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):  # Check if the packet is a Beacon
        # Extracting ESSID
        essid = pkt[Dot11Elt].info.decode(errors='ignore')
        # Extracting the BSSID (AP MAC address)
        bssid = pkt[Dot11].addr3
        
        # Update network_data
        if essid:
            network_data[bssid]['essid'] = essid
            network_data[bssid]['beacons'] += 1

# Function to continuously sniff packets
def sniff_packets():
    sniff(prn=packet_handler, iface="WiFi", store=0, timeout=60)

# Function to update the GUI with the latest data
def update_gui():
    for bssid, data in network_data.items():
        essid = data['essid']
        beacons = data['beacons']
        network_listbox.insert(tk.END, f"BSSID: {bssid} | ESSID: {essid} | Beacons: {beacons}")
    # Update the GUI every 5 seconds to refresh the list
    root.after(5000, update_gui)

# Create the GUI window
root = tk.Tk()
root.title("WiFi Networks with Beacon Information")

# Create a listbox to show the Wi-Fi networks and beacons
network_listbox = tk.Listbox(root, width=50, height=20)
network_listbox.pack(pady=20)

# Start sniffing packets in a separate thread
sniffer_thread = threading.Thread(target=sniff_packets)
sniffer_thread.daemon = True
sniffer_thread.start()

# Start updating the GUI
update_gui()

# Run the GUI event loop
root.mainloop()
