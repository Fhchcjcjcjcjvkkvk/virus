import os
import time
import subprocess
import argparse
from pywifi import PyWiFi
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Function to get available networks using pywifi
def scan_networks_with_pywifi(interface):
    print(Fore.GREEN + f"[Scanning for Networks on interface {interface}...]")
    
    wifi = PyWiFi()  # Create a PyWiFi object
    iface = wifi.interfaces()[interface]  # Get the specified Wi-Fi interface

    iface.scan()  # Start scanning for networks
    time.sleep(2)  # Give it some time to scan
    
    networks = iface.scan_results()  # Get the scan results
    return networks

# Function to get encryption type of networks using netsh
def get_encryption_details():
    print(Fore.GREEN + "[Getting Encryption Details using netsh...]")
    
    # Run the netsh command to get Wi-Fi network details with encryption information
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    
    # Parse the result
    networks = []
    if result.returncode == 0:
        output = result.stdout.split('\n')
        network = {}
        for line in output:
            line = line.strip()
            if "SSID" in line:
                if network:
                    networks.append(network)
                network = {"SSID": line.split(":")[1].strip()}
            elif "BSSID" in line:
                network["BSSID"] = line.split(":")[1].strip()
            elif "Signal" in line:
                network["Signal"] = line.split(":")[1].strip()
            elif "Encryption" in line:
                network["Encryption"] = line.split(":")[1].strip()

        if network:  # Add the last network
            networks.append(network)
    
    return networks

# Function to get the interface index by name
def get_interface_index(interface_name):
    wifi = PyWiFi()
    interfaces = wifi.interfaces()
    
    # Print all available interfaces and their names
    print(Fore.YELLOW + "Available interfaces:")
    for index, iface in enumerate(interfaces):
        print(f"{index}: {iface.name}")

    # Look for the interface by name and return its index
    for index, iface in enumerate(interfaces):
        if iface.name == interface_name:
            return index
    return None  # Return None if the interface is not found

# Display the banner in green with the antenna in red
def print_banner():
    banner = f"""
    {Fore.GREEN}.;'                     `;,    
    .;'  ,;'             `;,  `;,  
    .;'  ,;'  ,;'     `;,  `;,  `;,  
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

# Main function to continuously scan and display networks with BSSID, signal strength, and encryption
def main(args):
    print_banner()
    try:
        # Get the interface index by name
        interface_index = get_interface_index(args.interface)
        if interface_index is None:
            print(Fore.RED + f"Interface '{args.interface}' not found.")
            return

        print(Fore.GREEN + f"Using interface: {args.interface} (Index: {interface_index})")
        
        while True:
            # Simulate loading bar before displaying networks
            for i in range(101):
                print_loading_bar(i / 100)
                time.sleep(0.05)

            # Get networks using pywifi
            networks = scan_networks_with_pywifi(interface_index)
            encryption_details = get_encryption_details()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<5}{'Encryption':<15}")

            # Create a dictionary for fast lookup of encryption details
            encryption_dict = {net["SSID"]: net["Encryption"] for net in encryption_details}

            # Print network details
            if networks:
                for net in networks:
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal
                    encryption_type = encryption_dict.get(ssid, "Unknown")

                    print(f"{bssid:<20}{ssid:<30}{signal_strength:<5}{encryption_type}")
            else:
                print(Fore.RED + "No networks found.")

            # Wait for a while before the next scan
            time.sleep(10)

    except KeyboardInterrupt:
        print("\nExiting...")
        exit()

# Set up argument parser
def parse_arguments():
    parser = argparse.ArgumentParser(description="Airscan - A Wi-Fi scanner using pywifi.")
    parser.add_argument(
        "interface", 
        type=str, 
        help="Name of the Wi-Fi interface to use for scanning (e.g., 'WiFi', 'Ethernet', etc.)."
    )
    return parser.parse_args()

# Run the program
if __name__ == "__main__":
    args = parse_arguments()
    main(args)
