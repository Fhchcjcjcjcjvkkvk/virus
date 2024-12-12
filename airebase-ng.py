import os
import time
import subprocess
from pywifi import PyWiFi
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Function to get authentication method using netsh for a given SSID
def get_authentication_method():
    try:
        # Run the netsh command to get network information (mode=Bssid shows more details)
        command = 'netsh wlan show networks'
        result = subprocess.check_output(command, shell=True, text=True)

        # Split the result into individual network blocks
        networks = result.split("\n\n")
        
        auth_methods = []
        for network in networks:
            auth_method = "Unknown"  # Default to "Unknown"
            
            # Parse the network block for Authentication method
            for line in network.splitlines():
                if "Authentication" in line:
                    auth_method = line.split(":")[1].strip()
                    auth_methods.append(auth_method)

        return auth_methods

    except Exception as e:
        print(f"Error fetching authentication method: {e}")
        return ["Unknown"]

# Function to get available networks using pywifi
def scan_networks_with_pywifi():
    print(Fore.GREEN + "[Scanning for Networks using pywifi...]")
    
    wifi = PyWiFi()  # Create a PyWiFi object
    iface = wifi.interfaces()[0]  # Get the first Wi-Fi interface (assuming it is the one used for scanning)

    iface.scan()  # Start scanning for networks
    time.sleep(2)  # Give it some time to scan
    
    networks = iface.scan_results()  # Get the scan results
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

# Main function to continuously scan and display networks with BSSID, signal strength, and authentication method
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

            # Get authentication methods using netsh
            auth_methods = get_authentication_method()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<6}{'Auth Method'}")

            # Print network details
            if networks:
                for i, net in enumerate(networks):
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal
                    # If there are more authentication methods than networks, we loop through them
                    auth_method = auth_methods[i] if i < len(auth_methods) else "Unknown"

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
