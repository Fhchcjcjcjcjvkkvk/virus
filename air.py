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

# Function to get the authentication methods using netsh
def get_authentication_methods():
    # Run the netsh command to show networks and capture the output
    result = subprocess.run(['netsh', 'wlan', 'show', 'networks'], capture_output=True, text=True)
    
    # Check if the command was successful
    if result.returncode != 0:
        print(Fore.RED + "Failed to retrieve network information using netsh.")
        return []

    output = result.stdout
    auth_methods = []
    
    # Search for lines with authentication method information
    for line in output.splitlines():
        if "Authentication" in line:
            # Extract the authentication method
            auth_method = line.split(":")[1].strip()
            auth_methods.append(auth_method)
    
    return auth_methods

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

            # Get networks using pywifi
            networks = scan_networks_with_pywifi()

            # Get the authentication methods using netsh
            auth_methods = get_authentication_methods()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<10}{'Auth Method'}")

            # Print network details with authentication method
            if networks:
                for net in networks:
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal

                    # Show authentication method for each network
                    auth_method = "Unknown"
                    if auth_methods:
                        auth_method = auth_methods[0]  # We can improve this by associating auth methods to specific networks if needed

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
