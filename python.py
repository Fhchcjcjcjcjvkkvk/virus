import pyshark

cap = pyshark.FileCapture("wpa.cap", display_filter="eapol")

for packet in cap:
    if hasattr(packet, 'eapol') and hasattr(packet.eapol, 'key'):
        try:
            anonce = packet.eapol.key.anonce
            snonce = packet.eapol.key.snonce
            print(f"ANonce: {anonce}, SNonce: {snonce}")
