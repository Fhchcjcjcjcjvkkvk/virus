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

# Function to get the authentication and cipher of networks using netsh
def get_auth_and_cipher():
    # Run the command to get the detailed network information
    try:
        result = subprocess.check_output('netsh wlan show networks mode=bssid', shell=True, encoding='utf-8')
        networks_info = []
        # Parse the output to get BSSID, Authentication, and Cipher information
        for line in result.splitlines():
            if "SSID" in line:
                ssid = line.split(":")[1].strip()
            if "BSSID" in line:
                bssid = line.split(":")[1].strip()
            if "Authentication" in line:
                auth = line.split(":")[1].strip()
            if "Cipher" in line:
                cipher = line.split(":")[1].strip()
                networks_info.append((ssid, bssid, auth, cipher))
        return networks_info
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Error getting network details with netsh.")
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

# Main function to continuously scan and display networks with BSSID, signal strength, authentication, and cipher
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

            # Get network authentication and cipher details using netsh
            netsh_networks = get_auth_and_cipher()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<6}{'Auth':<12}{'Cipher':<12}")

            # Print network details
            if networks:
                for net in networks:
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal
                    
                    # Get the corresponding auth and cipher for each network
                    for net_info in netsh_networks:
                        if net_info[1] == bssid:  # Match BSSID
                            auth = net_info[2]
                            cipher = net_info[3]
                            print(f"{bssid:<20}{ssid:<30}{signal_strength:<6}{auth:<12}{cipher:<12}")
                            break
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
