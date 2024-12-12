import os
import time
import subprocess
import argparse
from colorama import Fore, init

# Initialize colorama for colored output
init(autoreset=True)

# Function to scan networks and extract BSSID, ESSID, encryption type, and RSSI using tshark
def scan_networks_with_tshark(interface):
    print(Fore.GREEN + f"[Scanning for Networks on {interface} using tshark...]")
    
    # Run tshark to capture Wi-Fi packets and extract BSSID, ESSID, encryption type, and RSSI
    cmd = [
        "tshark", "-i", interface, "-Y", "wlan.fc.type_subtype == 0x08",  # Filter for Beacon frames
        "-T", "fields", "-e", "wlan.bssid", "-e", "wlan.ssid", "-e", "wlan.crypto", "-e", "wlan.signal_dbm"
    ]
    
    # Run the command and capture output
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.PIPE, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Error: Could not execute tshark. Ensure tshark is installed and the interface is correct.")
        print(e.output)
        return []
    
    # Parse the output to display results
    networks = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) == 4:
            bssid = fields[0].strip()
            essid = fields[1].strip()
            encryption = fields[2].strip()
            rssi = fields[3].strip()
            networks.append((bssid, essid, encryption, rssi))
    
    return networks

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

# Function to display the networks in a formatted way
def display_networks(networks):
    # Print the header
    print(Fore.RED + "==== Available Networks ====")
    print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'Encryption':<15}{'RSSI'}")
    
    # Print the network details
    if networks:
        for bssid, essid, encryption, rssi in networks:
            print(f"{bssid:<20}{essid:<30}{encryption:<15}{rssi}")
    else:
        print(Fore.RED + "No networks found.")

# Function to parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Scan Wi-Fi networks and display BSSID, ESSID, encryption type, and RSSI")
    parser.add_argument(
        "-i", "--interface",
        type=str,
        required=True,
        help="The name of the Wi-Fi interface to use for scanning (e.g., 'Wi-Fi')."
    )
    return parser.parse_args()

# Main function
def main():
    # Parse the command-line arguments
    args = parse_args()
    
    # Display the banner
    print_banner()
    
    # Simulate loading bar before starting the scan
    for i in range(101):
        print_loading_bar(i / 100)
        time.sleep(0.05)
    
    # Scan networks and get BSSID, ESSID, encryption type, and RSSI using tshark
    networks = scan_networks_with_tshark(args.interface)
    
    # Display the results
    display_networks(networks)

# Run the program
if __name__ == "__main__":
    main()
