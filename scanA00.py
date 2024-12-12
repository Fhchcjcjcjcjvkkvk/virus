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

# Function to get network details using netsh on Windows
def get_network_authentication():
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    
    networks = []
    if result.returncode == 0:
        output = result.stdout
        network_details = output.split("\n\n")
        
        for network in network_details:
            network_info = {}
            for line in network.splitlines():
                if "SSID" in line:
                    network_info["SSID"] = line.split(":")[1].strip()
                elif "BSSID" in line:
                    network_info["BSSID"] = line.split(":")[1].strip()
                elif "Signal" in line:
                    network_info["Signal"] = line.split(":")[1].strip()
                elif "Authentication" in line:
                    network_info["Authentication"] = line.split(":")[1].strip()
            if network_info:
                networks.append(network_info)
    
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

# Main function to continuously scan and display networks with BSSID and signal strength
def main():
    print_banner()
    try:
        while True:
            # Simulate loading bar before displaying networks
            for i in range(101):
                print_loading_bar(i / 100)
                time.sleep(0.05)

            # Get networks using netsh for detailed info
            networks = get_network_authentication()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'Signal':<10}{'Auth Method'}")

            # Print network details
            if networks:
                for net in networks:
                    bssid = net.get("BSSID", "N/A")
                    ssid = net.get("SSID", "N/A")
                    signal_strength = net.get("Signal", "N/A")
                    auth_method = net.get("Authentication", "N/A")

                    print(f"{bssid:<20}{ssid:<30}{signal_strength:<10}{auth_method}")
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
