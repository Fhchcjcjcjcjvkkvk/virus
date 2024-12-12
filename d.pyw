import os
import time
import subprocess
from pywifi import PyWiFi
from colorama import Fore, init
import re

# Initialize colorama
init(autoreset=True)

# Function to get available networks using pywifi
def scan_networks_with_pywifi():
    print(Fore.GREEN + "[Scanning for Networks using pywifi...]")
    
    wifi = PyWiFi()  # Create a PyWiFi object
    iface = wifi.interfaces()[0]  # Get the first Wi-Fi interface (assuming it is the one used for scanning)

    iface.scan()  # Start scanning for networks
    time.sleep(2)  # Give it some time to scan
    
    networks = iface.scan_results()  # Get the scan results
    return networks

# Function to get detailed network information using 'netsh' (Windows only)
def get_network_details():
    try:
        # Run the command to get Wi-Fi network details
        result = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True, text=True)
        
        # Extract relevant details using regular expressions
        networks_info = []
        network_entries = result.split('\n\n')

        for entry in network_entries:
            cipher = re.search(r"Cipher\s*:\s*(\S+)", entry)
            enc = re.search(r"Encryption\s*:\s*(\S+)", entry)
            ssid = re.search(r"SSID\s*:\s*(\S+)", entry)
            bssid = re.search(r"BSSID\s*:\s*([\da-fA-F:]+)", entry)

            if ssid and bssid:
                network_info = {
                    "ssid": ssid.group(1),
                    "bssid": bssid.group(1),
                    "cipher": cipher.group(1) if cipher else "N/A",
                    "encryption": enc.group(1) if enc else "N/A"
                }
                networks_info.append(network_info)

        return networks_info

    except subprocess.CalledProcessError:
        print(Fore.RED + "Failed to run netsh command. Ensure you're on Windows.")
        return []

# Display the banner in green with the antenna in red
def print_banner():
    banner = f"""
    {Fore.GREEN}.;'                     ;,    
    .;'  ,;'             ;,  ;,  
    .;'  ,;'  ,;'     ;,  ;,  ;,  
    ::   ::   :   ( )   :   ::   ::  
    {Fore.RED}':   ':   ':  /_\\ ,:'  ,:'  ,:'  
     ':   ':     /___\\    ,:'  ,:'   
      ':        /_____\\      ,:'     
               /       \\          
    """
    print(banner)

# Print a loading bar
def print_loading_bar(percentage):
    bar_length = 40
    block = int(round(bar_length * percentage))
    progress = "█" * block + "-" * (bar_length - block)
    print(f"\r[{percentage * 100:.0f}%|{progress}] ", end="")

# Main function to continuously scan and display networks with BSSID, Signal Strength, Cipher, and Encryption
def main():
    print_banner()
    try:
        while True:
            # Simulate loading bar before displaying networks
            for i in range(101):
                print_loading_bar(i / 100)
                time.sleep(0.05)

            # Get networks using pywifi
            networks = scan_networks_with_pywifi()

            # Get detailed network info using 'netsh'
            netsh_networks = get_network_details()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<6}{'CIPHER':<10}{'ENC':<10}")

            # Print network details
            if networks:
                for net in networks:
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal

                    # Find matching network details from 'netsh' output
                    matching_netsh = next((n for n in netsh_networks if n['bssid'] == bssid), None)
                    cipher = matching_netsh['cipher'] if matching_netsh else "N/A"
                    encryption = matching_netsh['encryption'] if matching_netsh else "N/A"

                    print(f"{bssid:<20}{ssid:<30}{signal_strength:<6}{cipher:<10}{encryption:<10}")
            else:
                print(Fore.RED + "No networks found.")

            # Wait for a while before the next scan
            time.sleep(10)

    except KeyboardInterrupt:
        print("\nExiting...")
        exit()

# Run the program
if __name__ == "__main__":
    main()
