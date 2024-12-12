import subprocess
import time
import sys
from termcolor import colored
from colorama import init

# Initialize colorama for Windows compatibility
init()

# Function to scan available networks (Windows)
def scan_networks():
    try:
        # Run the command to scan networks
        scan_result = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True, universal_newlines=True)
        return scan_result
    except subprocess.CalledProcessError as e:
        print(f"Error scanning networks: {e}")
        return None

# Function to parse the scan result
def parse_networks(scan_result):
    networks = []
    current_network = {}
    lines = scan_result.splitlines()
    
    for line in lines:
        if "BSSID" in line:  # New network entry
            if current_network:
                networks.append(current_network)
            current_network = {}
        elif "BSSID" in line:
            current_network['BSSID'] = line.split(":")[1].strip()
        elif "SSID" in line:
            current_network['ESSID'] = line.split(":")[1].strip()
        elif "Channel" in line:
            current_network['CH'] = line.split(":")[1].strip()
        elif "Encryption" in line:
            current_network['ENCR'] = line.split(":")[1].strip()
        elif "Signal" in line:
            current_network['RSSI'] = line.split(":")[1].strip().split()[0]
    
    if current_network:
        networks.append(current_network)  # Add last network
    return networks

# Function to print networks in columns
def print_networks(networks, elapsed_time):
    # Display elapsed time in minutes
    minutes = elapsed_time // 60
    print(f"{f'Elapsed: {minutes} min':<15}{'BSSID':<20}{'ESSID':<20}{'CH':<5}{'ENCR':<10}{'RSSI':<5}")
    for network in networks:
        print(f"{' ':<15}{network['BSSID']:<20}{network['ESSID']:<20}{network['CH']:<5}{network['ENCR']:<10}{network['RSSI']:<5}")

# Function to prompt user for interface
def get_user_input():
    interface = input("Enter INTERFACE (e.g., Wi-Fi): ")
    return interface

# Function to print colored banner with antenna in green
def print_banner():
    banner = """
    .;'                     ;,  ;,   
    .;'  ,;'             ;,  ;,   
    .;'  ,;'  ,;'     ;,  ;,  ;,  
    ::   ::   :   ( )   :   ::   ::  
    ':   ':   ':  /_\\ ,:'  ,:'  ,:'  
     ':   ':     /___\\    ,:'  ,:'   
      ':        /_____\     ,:'     
            /       \\         
    """
    # Color the waves (antenna) in green
    green_wave = """
    .;'  ,;'             ;,  ;,   
    .;'  ,;'  ,;'     ;,  ;,  ;,  
    ::   ::   :   ( )   :   ::   ::  
    """
    print(colored(".;'                     ;,  ;,", 'red'))
    print(colored(green_wave, 'green'))
    print(colored(".;'  ,;'             ;,  ;,", 'red'))
    print(colored(".;'  ,;'  ,;'     ;,  ;,  ;,", 'red'))
    print(colored("::   ::   :   ( )   :   ::   ::", 'red'))
    print(colored("':   ':   ':  /_\\ ,:'  ,:'  ,:'", 'red'))
    print(colored(" ':   ':     /___\\    ,:'  ,:'", 'red'))
    print(colored("  ':        /_____\\     ,:'", 'red'))
    print(colored("            /       \\         ", 'red'))

# Function to show a loading bar animation
def show_loading_bar():
    # Simulate loading progress for 5 seconds
    total_steps = 50
    for i in range(total_steps + 1):
        percent = (i * 100) // total_steps
        bar = '█' * i + ' ' * (total_steps - i)
        sys.stdout.write(f"\r[{percent:3d}%|{bar}]")
        sys.stdout.flush()
        time.sleep(0.1)  # Simulate delay (you can adjust this to speed up or slow down)
    sys.stdout.write("\n")  # Move to the next line after the bar

# Main function to combine everything
def main():
    print_banner()

    start_time = time.time()  # Record the start time

    while True:
        print("\nScanning for networks...")
        show_loading_bar()  # Show loading bar animation
        
        scan_result = scan_networks()
        
        if scan_result:
            networks = parse_networks(scan_result)
            elapsed_time = time.time() - start_time  # Calculate elapsed time
            print_networks(networks, elapsed_time)
        
        interface = get_user_input()  # Get the interface input (no BSSID input now)
        
        time.sleep(5)  # Wait before next scan

if __name__ == "__main__":
    main()
