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

# Function to get encryption and authentication from netsh for each network SSID
def get_encryption_and_auth_from_netsh(ssid):
    print(f"Checking encryption and authentication for network: {ssid}")
    result = subprocess.run(
        ["netsh", "wlan", "show", "network", "name=" + ssid],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(Fore.RED + f"Error: Unable to fetch encryption and authentication details for {ssid}.")
        return "Unknown", "Unknown"
    
    encryption = "Unknown"
    authentication = "Unknown"
    
    # Search for encryption and authentication lines in the netsh output
    for line in result.stdout.split("\n"):
        if "Encryption" in line:
            encryption = line.split(":")[1].strip()
        elif "Authentication" in line:
            authentication = line.split(":")[1].strip()
    
    return encryption, authentication

# Display the banner in green with the antenna in red
def print_banner():
    banner = f"""
    {Fore.GREEN}.;'                     `;,    
    .;'  ,;'             `;,  `;,  
    .;'  ,;'  ,;'     `;,  `;,  `;,  
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

# Main function to continuously scan and display networks with encryption, authentication, and BSSID info
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
            print(Fore.GREEN + f"{'BSSID':<20}{'SSID':<30}{'Signal Strength':<15}{'Encryption':<15}{'Authentication'}")

            # Print network details
            if networks:
                for net in networks:
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal
                    
                    # Get encryption and authentication type from netsh
                    encryption, authentication = get_encryption_and_auth_from_netsh(ssid)

                    print(f"{bssid:<20}{ssid:<30}{signal_strength:<15}{encryption:<15}{authentication}")
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
