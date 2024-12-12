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

# Function to get the authentication method using netsh (Windows only)
def get_network_authentication():
    try:
        # Run netsh command to get details about the Wi-Fi networks
        result = subprocess.check_output('netsh wlan show networks mode=bssid', shell=True, text=True)

        # Find the authentication method in the output
        auth_method = None
        for line in result.splitlines():
            if "Authentication" in line:
                auth_method = line.split(":")[1].strip()

                # Check and return specific authentication methods
                if "WPA3" in auth_method:
                    return "WPA3"
                elif "WPA2" in auth_method:
                    return "WPA2"
                elif "WPA" in auth_method:
                    return "WPA"
                elif "WEP" in auth_method:
                    return "WEP"
                elif "Open" in auth_method:
                    return "Open"
                else:
                    return auth_method
        return "Unknown"  # If the method is not found
    except subprocess.CalledProcessError:
        return None

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

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<10}{'Auth Method':<20}")

            # Print network details
            if networks:
                for net in networks:
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal

                    # Get the authentication method for the network (Windows only)
                    auth_method = get_network_authentication()

                    # Print the network information including the authentication method
                    print(f"{bssid:<20}{ssid:<30}{signal_strength:<10}{auth_method if auth_method else 'Unknown'}")
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
