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

# Function to get the authentication and encryption method using netsh (for Windows)
def get_network_authentication_and_encryption():
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    
    if result.returncode != 0:
        print("Error scanning networks with netsh.")
        return []

    output = result.stdout
    networks = output.split("\n")
    
    network_details = []
    
    ssid = ""
    auth_type = ""
    encryption = ""
    
    for line in networks:
        if "SSID" in line:
            ssid = line.split(":")[1].strip()
        if "Authentication" in line:
            auth_type = line.split(":")[1].strip()
        if "Encryption" in line:
            encryption = line.split(":")[1].strip()
        if "BSSID" in line:
            bssid = line.split(":")[1].strip()
        if "Signal" in line:
            signal_strength = line.split(":")[1].strip()
            # Append the details for each network once all info is collected
            network_details.append({
                "BSSID": bssid,
                "SSID": ssid,
                "Signal": signal_strength,
                "Authentication": auth_type,
                "Encryption": encryption
            })
    
    return network_details

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

            # Get authentication and encryption methods using netsh
            network_details = get_network_authentication_and_encryption()

            # Clear screen before printing new results
            os.system("cls" if os.name == "nt" else "clear")

            # Print the header
            print(Fore.RED + "==== Available Networks ====")
            print(Fore.GREEN + f"{'BSSID':<20}{'ESSID':<30}{'PWR':<10}{'Authentication':<20}{'Encryption'}")

            # Print network details using pywifi and netsh
            if networks:
                for net in networks:
                    bssid = net.bssid
                    ssid = net.ssid
                    signal_strength = net.signal
                    
                    # Match network info from pywifi with netsh details
                    for details in network_details:
                        if details['SSID'] == ssid:  # Match by SSID
                            print(f"{details['BSSID']:<20}{details['SSID']:<30}{signal_strength:<10}{details['Authentication']:<20}{details['Encryption']}")

            else:
                print(Fore.RED + "No networks found using pywifi.")

            # Wait for a while before the next scan
            time.sleep(10)

    except KeyboardInterrupt:
        print("\nExiting...")
        exit()

# Run the program
if __name__ == "__main__":
    main()
