import os
import time
import subprocess
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Function to get available networks using Windows netsh command
def scan_networks():
    print(Fore.GREEN + "[Scanning for Networks...]")
    # Run the Windows command to list available Wi-Fi networks
    result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True)
    networks = result.stdout.split("\n")
    return networks

# Parse network information from the netsh output
def parse_networks(networks):
    parsed_networks = []
    network_info = {}
    for line in networks:
        if "BSSID" in line:
            if network_info:
                parsed_networks.append(network_info)
            network_info = {"BSSID": line.split(":")[1].strip()}
        elif "SSID" in line:
            network_info["ESSID"] = line.split(":")[1].strip()
        elif "Channel" in line:
            network_info["Channel"] = line.split(":")[1].strip()
        elif "Encryption" in line:
            network_info["Encryption"] = line.split(":")[1].strip()
        elif "Signal" in line:
            network_info["RSSI"] = line.split(":")[1].strip()
    if network_info:
        parsed_networks.append(network_info)
    return parsed_networks

# Display the banner in green
def print_banner():
    banner = f"""
    {Fore.GREEN}.;'  ,;'             `;,  `;,   
    .;'  ,;'  ,;'     `;,  `;,  `;,  
    ::   ::   :   ( )   :   ::   ::  
    ':   ':   ':  /_\\ ,:'  ,:'  ,:'  
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

# Function to continuously scan and display networks
def main():
    print_banner()
    try:
        while True:
            # Simulate loading bar before displaying networks
            for i in range(101):
                print_loading_bar(i / 100)
                time.sleep(0.05)

            # Get and parse network data
            networks = scan_networks()
            parsed_networks = parse_networks(networks)

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'Channel':<8}{'Encryption':<15}{'RSSI'}")

            # Print network details
            for net in parsed_networks:
                print(f"{net.get('BSSID', 'N/A'):<20}{net.get('ESSID', 'N/A'):<30}{net.get('Channel', 'N/A'):<8}{net.get('Encryption', 'N/A'):<15}{net.get('RSSI', 'N/A')}")

            # Wait for a while before the next scan
            time.sleep(10)

    except KeyboardInterrupt:
        print("\nExiting...")
        exit()

# Run the program
if __name__ == "__main__":
    main()
