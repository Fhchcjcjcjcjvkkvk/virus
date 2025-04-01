import pyshark

def extract_handshake(pcap_file):
    # Read the pcap file
    cap = pyshark.FileCapture(pcap_file, display_filter="eapol")

    # Create a list to store EAPOL packets
    eapol_packets = []

    # Iterate through the packets and collect EAPOL packets
    for packet in cap:
        if 'eapol' in packet:
            eapol_packets.append(packet)

    return eapol_packets

def extract_key_info(eapol_packets):
    key_info = []

    # Iterate over the EAPOL packets to extract key fields
    for packet in eapol_packets:
        if hasattr(packet.eapol, 'keymic'):
            # Extract the WPA Key MIC (16 bytes)
            key_mic = packet.eapol.keymic
            print(f"Extracted WPA Key MIC: {key_mic}")

        if hasattr(packet.eapol, 'keynonce'):
            # Extract the WPA Key Nonce (32 bytes)
            key_nonce = packet.eapol.keynonce
            print(f"Extracted WPA Key Nonce: {key_nonce}")

        if hasattr(packet.eapol, 'keyiv'):
            # Extract the WPA Key IV (16 bytes)
            key_iv = packet.eapol.keyiv
            print(f"Extracted WPA Key IV: {key_iv}")

        # Append the values to the list (for further analysis)
        key_info.append({
            'key_mic': key_mic if hasattr(packet.eapol, 'keymic') else None,
            'key_nonce': key_nonce if hasattr(packet.eapol, 'keynonce') else None,
            'key_iv': key_iv if hasattr(packet.eapol, 'keyiv') else None
        })
    
    return key_info

# Example usage:
pcap_file = 'shak.cap'  # Path to the .cap file containing the WPA handshake

# Step 1: Extract EAPOL packets
eapol_packets = extract_handshake(pcap_file)

# Step 2: Extract the key-related information from the EAPOL packets
key_info = extract_key_info(eapol_packets)

# Print all extracted information
for info in key_info:
    print(info)
