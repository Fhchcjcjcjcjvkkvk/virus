import argparse
import pyshark

def extract_psk_and_bssid(capture_file):
    try:
        # Open the pcap or cap file using pyshark
        capture = pyshark.FileCapture(capture_file, display_filter="wlan.fc.type_subtype == 0x08")  # WPA Handshake filter

        # Loop through each packet in the capture
        for packet in capture:
            # Check for handshake messages
            if 'eapol' in packet:
                # Extract the BSSID (MAC address of the AP)
                bssid = packet.wlan.bssid
                # Extract the encrypted PSK (this is part of the EAPOL message)
                if 'wlan.eapol.key.iv' in packet:
                    encrypted_psk = packet.wlan.eapol.key.iv  # Only get the encrypted part of the PSK

                    # Print the results
                    print(f"BSSID: {bssid}")
                    print(f"Encrypted PSK: {encrypted_psk}")
                    return

        print("No WPA handshake with PSK found in the capture file.")
    except Exception as e:
        print(f"Error processing capture file: {e}")

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Extract BSSID and encrypted PSK from WPA handshake capture file.")
    parser.add_argument("capture_file", help="Path to the .pcap or .cap handshake capture file")
    args = parser.parse_args()

    # Extract PSK and BSSID from the provided capture file
    extract_psk_and_bssid(args.capture_file)

if __name__ == "__main__":
    main()
