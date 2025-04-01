import pyshark

cap = pyshark.FileCapture("wpa.cap", display_filter="eapol")

for packet in cap:
    print(packet)
