import subprocess
import argparse

def scan_networks():
    # Run the command to scan for available Wi-Fi networks
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    
    if result.returncode != 0:
        print("Error scanning networks")
        return
    
    output = result.stdout
    networks = output.split("\n")
    return networks

def show_bssids(networks):
    """Show the BSSIDs (MAC addresses of APs)"""
    for line in networks:
        if "BSSID" in line:
            bssid = line.split(":")[1].strip()
            print(f"BSSID: {bssid}")

def show_ssids(networks):
    """Show the SSIDs (network names)"""
    for line in networks:
        if "SSID" in line:
            ssid = line.split(":")[1].strip()
            print(f"SSID: {ssid}")

def show_encryption(networks):
    """Show the encryption types and authentication methods"""
    for line in networks:
        if "Encryption" in line:
            encryption = line.split(":")[1].strip()
            print(f"Encryption: {encryption}")
        if "Authentication" in line:
            auth_type = line.split(":")[1].strip()
            print(f"Authentication: {auth_type}")
        print("----------------------------")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Wi-Fi Network Information Tool")
    parser.add_argument('-b', '--bssids', action='store_true', help="Show BSSIDs of available networks")
    parser.add_argument('-s', '--ssids', action='store_true', help="Show SSIDs of available networks")
    parser.add_argument('-e', '--encryption', action='store_true', help="Show Encryption and Authentication methods")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Scan for networks
    networks = scan_networks()
    
    if args.bssids:
        show_bssids(networks)
    
    if args.ssids:
        show_ssids(networks)
    
    if args.encryption:
        show_encryption(networks)

if __name__ == "__main__":
    main()
