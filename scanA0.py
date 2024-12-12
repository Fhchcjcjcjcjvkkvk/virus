import os
import time
import subprocess
from pywifi import PyWiFi
from colorama import Fore, init

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

# Function to get network authentication details using netsh on Windows
def get_network_authentication():
    try:
        # Run the 'netsh' command to get detailed network information
        command = "netsh wlan show networks mode=bssid"
        output = subprocess.check_output(command, shell=True, universal_newlines=True)

        networks_info = []
        # Parse the output for each network
        network_details = output.split('\n\n')  # Split the output by each network

        for network in network_details:
            if network.strip():
                ssid = None
                auth_method = None
                # Look for SSID and authentication type (e.g., WPA2)
                for line in network.splitlines():
                    if "SSID" in line:
                        ssid = line.split(":")[1].strip()
                    if "Authentication" in line:
                        auth_method = line.split(":")[1].strip()

                if ssid and auth_method:
                    networks_info.append((ssid, auth_method))

        return networks_info
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Error retrieving authentication information.")
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

# Main function to continuously scan and display networks with BSSID, signal strength, and authentication
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

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Get authentication information using netsh
            auth_networks = get_network_authentication()

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<10}{'Authentication'}")

            # Print network details with authentication information
            if networks:
                for net in networks:
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal

                    # Try to find the authentication method for this network
                    auth_method = None
                    for auth_net in auth_networks:
                        if auth_net[0] == ssid:
                            auth_method = auth_net[1]
                            break

                    # If authentication method is found, print it; otherwise, print 'N/A'
                    if auth_method:
                        print(f"{bssid:<20}{ssid:<30}{signal_strength:<10}{auth_method}")
                    else:
                        print(f"{bssid:<20}{ssid:<30}{signal_strength:<10}{Fore.RED}N/A")

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
