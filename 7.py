import pywifi
from pywifi import PyWiFi

wifi = PyWiFi()
iface = wifi.interfaces()[0]  # Use the first wireless interface

# Start scanning for available networks
iface.scan()
results = iface.scan_results()

# Print the details of each network
for network in results:
    print(f"SSID: {network.ssid}")
    print(f"Signal Strength: {network.signal}")
    print(f"Security: {network.akm}")
    
    # Check if the channel attribute exists for the network
    if hasattr(network, 'channel'):
        print(f"Channel: {network.channel}")
    else:
        print("Channel: Not available")
    
    print('-' * 40)
