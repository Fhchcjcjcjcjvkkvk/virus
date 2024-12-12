import os
import time
import subprocess
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Function to get network authentication method using netsh
def get_networks_with_netsh():
    print(Fore.GREEN + "[Scanning for Networks using netsh...]")
    
    try:
        # Run the netsh command to get network information
        command = 'netsh wlan show networks mode=Bssid'
        result = subprocess.check_output(command, shell=True, text=True)

        # Split the result into individual network blocks
        networks = result.split("\n\n")
        network_info = []

        for network in networks:
            bssid = None
            ssid = None
            signal_strength = None
            auth_method = "Unknown"

            # Parse the network block for BSSID, SSID, Signal, and Authentication method
            for line in network.splitlines():
                if "BSSID" in line:
                    bssid = line.split(":")[1].strip()
                elif "SSID" in line:
                    ssid = line.split(":")[1].strip()
                elif "Signal" in line:
                    signal_strength = line.split(":")[1].strip()
                elif "Authentication" in line:
                    auth_method = line.split(":")[1].strip()

            # Only include valid networks with necessary information
            if bssid and ssid:
                network_info.append({
                    "bssid": bssid,
                    "ssid": ssid,
                    "signal_strength": signal_strength,
                    "auth_method": auth_method
                })

        return network_info

    except Exception as e:
        print(f"Error fetching network details: {e}")
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

# Main function to continuously scan and display networks with BSSID, signal strength, and authentication method
def main():
    print_banner()
    try:
        while True:
            # Simulate loading bar before displaying networks
            for i in range(101):
                print_loading_bar(i / 100)
                time.sleep(0.05)

            # Get networks using netsh
            networks = get_networks_with_netsh()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<6}{'Auth Method'}")

            # Print network details
            if networks:
                for net in networks:
                    bssid = net['bssid']
                    ssid = net['ssid']
                    signal_strength = net['signal_strength']
                    auth_method = net['auth_method']

                    print(f"{bssid:<20}{ssid:<30}{signal_strength:<6}{auth_method}")
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
