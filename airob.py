import os
import time
import subprocess
import argparse
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Function to get available networks using tshark
def scan_networks_with_tshark(interface_name):
    print(Fore.GREEN + f"[Scanning for Networks on {interface_name} using tshark...]")
    
    # Run tshark to capture WiFi networks and get the output in a readable format
    try:
        # On Windows, we can use -i "Wi-Fi" instead of the interface name (example: 'Wi-Fi' or 'Ethernet')
        command = [
            'tshark', '-i', interface_name, '-a', 'duration:10', '-T', 'fields',
            '-e', 'wlan.ssid', '-e', 'wlan.bssid', '-e', 'wlan.signal_strength'
        ]
        
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Parse the output from tshark
        networks = []
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) >= 3:
                ssid = fields[0]
                bssid = fields[1]
                signal_strength = fields[2]
                networks.append((bssid, ssid, signal_strength))
        
        return networks

    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error running tshark: {e}")
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

# Main function to continuously scan and display networks with BSSID and signal strength
def main():
    parser = argparse.ArgumentParser(description="WiFi Network Scanner using tshark on Windows")
    parser.add_argument("interface", type=str, help="Name of the WiFi interface (e.g., Wi-Fi, Ethernet)")
    args = parser.parse_args()
    
    print_banner()
    
    try:
        while True:
            # Simulate loading bar before displaying networks
            for i in range(101):
                print_loading_bar(i / 100)
                time.sleep(0.05)

            # Get networks using tshark
            networks = scan_networks_with_tshark(args.interface)

            # Clear screen before printing new results
            os.system("cls")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'Signal Strength'}")

            # Print network details
            if networks:
                for bssid, ssid, signal_strength in networks:
                    print(f"{bssid:<20}{ssid:<30}{signal_strength}")
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
