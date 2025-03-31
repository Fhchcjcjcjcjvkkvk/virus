import pyshark

def extract_eapol_from_pcap(pcap_file):
    # Open the capture file with pyshark
    cap = pyshark.FileCapture(pcap_file, display_filter="eapol")

    eapol_frames = []

    # Loop through packets and extract EAPOL frames
    for packet in cap:
        if 'eapol' in packet:
            eapol_frames.append(packet)

    return eapol_frames

# Example usage
pcap_file = 'Shak.pcap'  # Replace with your capture file path
eapol_frames = extract_eapol_from_pcap(pcap_file)

# Print out some info about the extracted EAPOL frames
for i, frame in enumerate(eapol_frames):
    print(f"Frame {i+1}:")
    print(f"  Time: {frame.sniff_time}")
    print(f"  Source MAC: {frame.eth.src}")
    print(f"  Destination MAC: {frame.eth.dst}")
    print(f"  EAPOL Version: {frame.eapol.version}")
    print(f"  EAPOL Type: {frame.eapol.type}")
    print("-" * 40)
