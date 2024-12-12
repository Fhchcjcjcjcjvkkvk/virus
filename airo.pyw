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

# Function to get network security details using netsh
def get_network_security_details():
    try:
        # Run the netsh command to get network details
        result = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"], text=True)
        
        # Parse the result
        networks_details = []
        current_network = {}

        for line in result.splitlines():
            if "SSID" in line:
                if current_network:
                    networks_details.append(current_network)
                current_network = {'SSID': line.split(":")[1].strip()}
            elif "Authentication" in line:
                current_network['Auth'] = line.split(":")[1].strip()
            elif "Cipher" in line:
                current_network['Cipher'] = line.split(":")[1].strip()
            elif "Encryption" in line:
                # The 'Encryption' line usually gives WPA/WPA2 etc.
                encryption = line.split(":")[1].strip()
                current_network['ENC'] = encryption

        if current_network:
            networks_details.append(current_network)

        return networks_details

    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error running netsh: {e}")
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
    print_banner()
    try:
        while True:
            # Simulate loading bar before displaying networks
            for i in range(101):
                print_loading_bar(i / 100)
                time.sleep(0.05)

            # Get networks using pywifi
            networks = scan_networks_with_pywifi()

            # Get network security details using netsh
            network_security_details = get_network_security_details()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<10}{'Auth':<20}{'Cipher':<15}{'ENC':<10}")

            # Print network details
            if networks and network_security_details:
                for net, security in zip(networks, network_security_details):
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal
                    auth = security.get('Auth', 'N/A')
                    cipher = security.get('Cipher', 'N/A')
                    encryption = security.get('ENC', 'N/A')

                    print(f"{bssid:<20}{ssid:<30}{signal_strength:<10}{auth:<20}{cipher:<15}{encryption:<10}")
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
