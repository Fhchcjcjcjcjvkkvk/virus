import subprocess

# Function to scan for Wi-Fi networks using 'netsh'
def scan_wifi():
    # Run 'netsh wlan show networks mode=bssid' to list available networks with BSSID and signal strength
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    
    # Check if the command executed successfully
    if result.returncode != 0:
        print("Error running the command.")
        return

    # Output of the command
    output = result.stdout
    
    # Split the output into lines and parse the ESSID, BSSID, and Signal Strength
    lines = output.splitlines()
    networks = []
    current_network = {}

    for line in lines:
        # ESSID line
        if "SSID" in line and "BSSID" not in line:
            if current_network:  # Save previous network data if present
                networks.append(current_network)
                current_network = {}  # Reset for next network
            current_network['ESSID'] = line.split(":")[1].strip()
        
        # BSSID line
        if "BSSID" in line:
            current_network['BSSID'] = line.split(":")[1].strip()
        
        # Signal Strength line (RSSI)
        if "Signal" in line:
            # Extract signal strength in dBm (without percentage)
            current_network['Signal Strength'] = line.split(":")[1].strip()

    # Add the last network if present
    if current_network:
        networks.append(current_network)

    # Display the networks with ESSID, BSSID, and Signal Strength in dBm
    print(f"{'ESSID':<30} {'BSSID':<20} {'Signal Strength (dBm)'}")
    print("="*70)
    for network in networks:
        print(f"{network['ESSID']:<30} {network['BSSID']:<20} {network.get('Signal Strength', 'Not Available')}")

# Call the scan_wifi function
scan_wifi()
