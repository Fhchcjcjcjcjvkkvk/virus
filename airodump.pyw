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

# Function to get cipher type using netsh (Windows only)
def get_cipher_from_netsh(bssid):
    try:
        # Run the netsh command to get network information
        command = f'netsh wlan show networks mode=bssid'
        result = subprocess.check_output(command, shell=True, universal_newlines=True)

        # Check if the BSSID exists in the output and extract the cipher information
        if bssid in result:
            lines = result.splitlines()
            cipher = "Unknown"
            
            # Search for the line containing "Encryption" which indicates the cipher
            for line in lines:
                if "Encryption" in line:
                    cipher = line.split(":")[1].strip()
                    break

            # We want to return the cipher type like "WEP", "CCMP", "TKIP"
            return cipher if cipher else "Unknown"
    
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error fetching cipher: {e}")
    return "Unknown"

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

# Main function to continuously scan and display networks with BSSID, ESSID, signal strength, and cipher
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

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<6}{'Cipher'}")

            # Print network details
            if networks:
                for net in networks:
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal
                    cipher = get_cipher_from_netsh(bssid)  # Fetch the cipher for the network

                    print(f"{bssid:<20}{ssid:<30}{signal_strength:<6}{cipher}")
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