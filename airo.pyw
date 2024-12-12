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

# Function to run netsh command and get network details (AUTH, CIPHER, ENC)
def get_network_details():
    result = subprocess.run(["netsh", "wlan", "show", "network"], capture_output=True, text=True)
    output = result.stdout.splitlines()
    
    networks = []
    network_info = {}
    
    for line in output:
        if "SSID" in line:
            if network_info:
                networks.append(network_info)
            network_info = {"SSID": line.split(":")[1].strip()}
        elif "Authentication" in line:
            network_info["AUTH"] = line.split(":")[1].strip()
        elif "Cipher" in line:
            network_info["CIPHER"] = line.split(":")[1].strip()
        elif "Encryption" in line:
            network_info["ENC"] = line.split(":")[1].strip()
    
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

            # Get networks using pywifi
            networks = scan_networks_with_pywifi()
            
            # Get detailed network information using netsh
            network_details = get_network_details()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'SSID':<30}{'AUTH':<20}{'CIPHER':<20}{'ENC':<20}{'PWR'}")

            # Print network details
            if networks:
                for i, net in enumerate(networks):
                    ssid = net.ssid
                    signal_strength = net.signal
                    auth = network_details[i].get("AUTH", "N/A")
                    cipher = network_details[i].get("CIPHER", "N/A")
                    enc = network_details[i].get("ENC", "N/A")

                    print(f"{ssid:<30}{auth:<20}{cipher:<20}{enc:<20}{signal_strength}")
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
