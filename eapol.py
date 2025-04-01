import argparse
import pyshark

def extract_wpa_info(pcap_file):
    try:
        # Open the pcap file using pyshark
        capture = pyshark.FileCapture(pcap_file)

        for packet in capture:
            if 'WPA EAPOL' in packet:
                try:
                    wpa_layer = packet['WPA EAPOL']
                    key_nonce = wpa_layer.key_nonce
                    replay_counter = wpa_layer.replay_counter
                    print(f'Key Nonce: {key_nonce}')
                    print(f'Replay Counter: {replay_counter}')
                except AttributeError:
                    pass

    except FileNotFoundError:
        print(f"Error: The file '{pcap_file}' was not found.")
    except pyshark.FileCaptureError as e:
        print(f"Error: Could not open file '{pcap_file}'. Details: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract WPA Key Nonce and Replay Counter from a pcap file.')
    parser.add_argument('-f', '--file', required=True, help='Path to the pcap file')
    args = parser.parse_args()
    
    extract_wpa_info(args.file)
