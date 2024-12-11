import pywifi
from pywifi import PyWiFi, const

wifi = PyWiFi()
iface = wifi.interfaces()[0]  # Use the first wireless interface

# Start scanning for available networks
iface.scan()
results = iface.scan_results()

# Print the details of each network
for network in results:
    print(f"SSID: {network.ssid}")
    print(f"Channel: {network.channel}")
    print(f"Signal Strength: {network.signal}")
    print(f"Security: {network.akm}")
    print('-' * 40)
