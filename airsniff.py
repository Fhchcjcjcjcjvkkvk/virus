import argparse
import subprocess
import pyshark
import os
import time
from tabulate import tabulate

def capture_networks(interface, output_file):
    # Run airgoose.exe to capture EAPOLS and show available networks
    airgoose_command = f"airgoose.exe {interface} -o {output_file}"
    subprocess.run(airgoose_command, shell=True)

def display_networks(capture_file):
    capture = pyshark.FileCapture(capture_file)
    networks = {}
    stations = {}

    for packet in capture:
        if 'wlan' in packet:
            try:
                bssid = packet.wlan.bssid
                pwr = packet.wlan_radio.signal_dbm if hasattr(packet.wlan_radio, 'signal_dbm') else -1
                channel = packet.wlan_radio.channel
                essid = packet.wlan.ssid if hasattr(packet.wlan, 'ssid') else 'Hidden'
                enc = 'Unknown'
                auth = 'Unknown'
                beacons = 0  # Placeholder for beacons count
                data_rate = 0  # Placeholder for data rate

                if bssid not in networks:
                    networks[bssid] = [pwr, beacons, data_rate, channel, enc, auth, essid]

                if 'wlan_mgt' in packet:
                    # Update encryption and authentication
                    if hasattr(packet.wlan_mgt, 'tag_interpretation'):
                        tag = packet.wlan_mgt.tag_interpretation
                        if 'WPA' in tag:
                            enc = 'WPA'
                        elif 'WEP' in tag:
                            enc = 'WEP'
                        else:
                            enc = 'OPN'
                        auth = 'PSK' if 'PSK' in tag else 'MGT'

                if 'wlan_radio' in packet:
                    networks[bssid][0] = pwr  # Update power
                    networks[bssid][1] += 1  # Increment beacons count
                    networks[bssid][2] += 1  # Increment data rate
                
            except AttributeError:
                pass

        if 'wlan.sa' in packet:
            sta = packet.wlan.sa
            if sta not in stations:
                stations[sta] = [pwr, '']

            if 'wlan_mgt' in packet:
                if hasattr(packet.wlan_mgt, 'tag_interpretation'):
                    tag = packet.wlan_mgt.tag_interpretation
                    if 'EAPOL' in tag:
                        stations[sta][1] = 'EAPOL'
                    if 'Probe Request' in tag:
                        if hasattr(packet.wlan_mgt, 'ssid'):
                            stations[sta][1] = packet.wlan_mgt.ssid

    print("Networks:")
    headers = ["BSSID", "PWR", "Beacons", "#/s", "CH", "ENC", "AUTH", "ESSID"]
    network_list = [[bssid] + details for bssid, details in networks.items()]
    print(tabulate(network_list, headers=headers))

    print("\nStations:")
    headers = ["STATION", "PWR", "Notes", "Probes"]
    station_list = [[sta] + details for sta, details in stations.items()]
    print(tabulate(station_list, headers=headers))

def main():
    parser = argparse.ArgumentParser(description="Live network capture and display using PyShark and airgoose.exe")
    parser.add_argument("interface", help="The network interface to capture on")
    parser.add_argument("output", help="The output file to save the capture")
    args = parser.parse_args()

    capture_networks(args.interface, args.output)

    while True:
        os.system('cls')
        display_networks(args.output)
        time.sleep(5)

if __name__ == "__main__":
    main()
