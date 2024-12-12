import pywifi
from pywifi import const
import time

def list_wifi_details():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]  # Vybereme první síťové rozhraní

    # Spuštění skenování
    iface.scan()
    time.sleep(2)  # Pauza pro dokončení skenování

    # Získání výsledků
    results = iface.scan_results()

    # Výpis informací o sítích
    print("Informace o dostupných sítích:")
    for idx, network in enumerate(results, start=1):
        print(f"\nSíť {idx}:")
        print(f"  SSID: {network.ssid}")
        print(f"  BSSID: {network.bssid}")
        print(f"  Signal: {network.signal}")
        print(f"  Frequency: {network.freq}")
        print(f"  Auth: {network.auth}")
        print(f"  Cipher: {network.cipher}")
        print(f"  AKM: {network.akm}")

# Spustit funkci
list_wifi_details()
