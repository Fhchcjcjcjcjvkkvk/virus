import os
import time
from pywifi import PyWiFi, const, Profile
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Function to scan networks using pywifi
def scan_networks():
    print(Fore.GREEN + "[Scanning for Networks...]")
    
    wifi = PyWiFi()  # Create a PyWiFi object
    iface = wifi.interfaces()[0]  # Get the first Wi-Fi interface (assuming it is the one used for scanning)

    iface.scan()  # Start scanning for networks
    time.sleep(2)  # Give it some time to scan
    
    networks = iface.scan_results()  # Get the scan results
    return networks

# Function to map encryption types to human-readable strings
def get_encryption_str(encryption_type):
    if encryption_type == const.AUTH_ALG_OPEN:
        return "None"
    elif encryption_type == const.AUTH_ALG_WEP:
        return "WEP"
    elif encryption_type == const.AUTH_ALG_WPA:
        return "WPA/WPA2"
    elif encryption_type == const.AUTH_ALG_WPA3:
        return "WPA3"
    else:
        return "Unknown"

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

# Function to continuously scan and display networks
def main():
    print_banner()
    try:
        while True:
            # Simulate loading bar before displaying networks
            for i in range(101):
                print_loading_bar(i / 100)
                time.sleep(0.05)

            # Get and parse network data
            networks = scan_networks()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'SSID':<30}{'Signal Strength':<15}{'Encryption'}")

            # Print network details
            if networks:
                for net in networks:
                    ssid = net.ssid
                    signal_strength = net.signal
                    encryption = get_encryption_str(net.encryption)
                    
                    print(f"{ssid:<30}{signal_strength:<15}{encryption}")
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
