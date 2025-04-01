import pyshark

cap = pyshark.FileCapture("Shak.pcap", display_filter="eapol")

for packet in cap:
    if "EAPOL" in packet:
        try:
            mic = packet.wlan.eapol.key_mic
            print(f"Found MIC: {mic}")
        except AttributeError:
            pass
