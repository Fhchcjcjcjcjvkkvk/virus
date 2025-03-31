import argparse
import pyshark
import os
import signal
import sys

# Function to handle user interruption
def signal_handler(sig, frame):
    print("\nCapture stopped by user.")
    sys.exit(0)

# Register the signal handler for CTRL+C
signal.signal(signal.SIGINT, signal_handler)

def capture_packets(interface, output=None, timeout=3600):
    capture = pyshark.LiveCapture(interface=interface)
    networks = {}
    clients = {}

    def process_packet(packet):
        if 'WLAN' in packet:
            wlan_layer = packet['WLAN']
            if 'wlan.fc.type_subtype' in wlan_layer.field_names:
                type_subtype = wlan_layer['wlan.fc.type_subtype']
                if type_subtype == '0x08' or type_subtype == '0x05':  # Beacon or Probe Response
                    bssid = wlan_layer['wlan.bssid']
                    essid = wlan_layer.ssid if 'wlan.ssid' in wlan_layer else 'Unknown'
                    channel = wlan_layer.ds_channel if 'wlan.ds.channel' in wlan_layer else 'Unknown'
                    power = int(wlan_layer.rssi_dbm) if 'wlan.rssi.dbm' in wlan_layer else -1
                    beacons = int(wlan_layer.get('wlan_mgt.fixed.beacon', 0))
                    enc = 'OPN' if 'wlan.wep' not in wlan_layer else 'WEP'
                    auth = 'Unknown'

                    networks[bssid] = {
                        'PWR': power,
                        'Beacons': beacons,
                        '#/s': 0,
                        'CH': channel,
                        'ENC': enc,
                        'AUTH': auth,
                        'ESSID': essid
                    }
                elif type_subtype == '0x20':  # Data frames
                    bssid = wlan_layer['wlan.bssid']
                    if bssid in networks:
                        networks[bssid]['#/s'] += 1

            if 'wlan.ta' in wlan_layer.field_names:
                station = wlan_layer['wlan.ta']
                power = int(wlan_layer.rssi_dbm) if 'wlan.rssi.dbm' in wlan_layer else -1
                probes = wlan_layer.ssid if 'wlan.ssid' in wlan_layer else 'Unknown'
                notes = 'EAPOL' if 'eapol' in packet else ''

                clients[station] = {
                    'PWR': power,
                    'Notes': notes,
                    'Probes': probes
                }

    capture.apply_on_packets(process_packet, timeout=timeout)

    os.system('cls')
    print("BSSID              PWR   Beacons    #/s  CH ENC  AUTH ESSID")
    for bssid, data in networks.items():
        print(f"{bssid}   {data['PWR']}  {data['Beacons']}  {data['#/s']}  {data['CH']}  {data['ENC']}  {data['AUTH']} {data['ESSID']}")

    print("\nSTATION            PWR   Notes  Probes")
    for station, data in clients.items():
        print(f"{station}   {data['PWR']}  {data['Notes']}  {data['Probes']}")

    if output:
        capture.sniff(timeout=timeout)
        capture.save_to_file(output + '.pcap')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Capture Wi-Fi networks and clients')
    parser.add_argument('interface', help='Network interface to capture packets from')
    parser.add_argument('-o', '--output', help='Save the capture to a .pcap file', required=False)

    args = parser.parse_args()
    capture_packets(args.interface, args.output)
