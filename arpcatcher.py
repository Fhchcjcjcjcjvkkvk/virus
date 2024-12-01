import pyshark
import os
import time
import platform

# Get the default Downloads directory based on the OS
def get_downloads_directory():
    if platform.system() == 'Windows':
        return os.path.join(os.environ['USERPROFILE'], 'Downloads')
    elif platform.system() == 'Darwin':  # macOS
        return os.path.join(os.path.expanduser('~'), 'Downloads')
    else:  # Linux
        return os.path.join(os.path.expanduser('~'), 'Downloads')

# Function to validate interface
def validate_interface(interface):
    try:
        # Check if the interface is available
        capture = pyshark.LiveCapture(interface=interface)
        capture.close()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

# Function to start capturing
def capture_packets(interface, bssid, ssid, capture_filename, capture_duration):
    capture_dir = get_downloads_directory()

    # Full file path for capture
    capture_file = os.path.join(capture_dir, capture_filename + ".cap")

    # Define capture filter for BSSID and SSID (adjust as necessary)
    capture_filter = f"wlan addr1 {bssid}"

    if ssid:
        capture_filter += f" and wlan ssid {ssid}"

    # Start capturing with PyShark
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter)

    # Start capturing and write to file
    print(f"Starting capture on {interface} for BSSID: {bssid}, SSID: {ssid}...")
    capture.sniff(timeout=capture_duration)  # Capture for the specified duration

    print(f"Saving capture to {capture_file}")
    capture.dump_packets(capture_file)

# Main function
def main():
    interface = input("Enter the interface name to capture (e.g., wlan0): ")

    # Validate interface
    if not validate_interface(interface):
        print("Invalid interface. Exiting...")
        return

    bssid = input("Enter the BSSID to capture packets from: ")
    ssid = input("Enter the SSID to capture packets from (leave blank if not needed): ")
    capture_filename = input("Enter the name of the capture file (without extension): ")
    capture_duration = int(input("Enter the capture duration in seconds (default is 60): ") or 60)

    # Start the capture
    capture_packets(interface, bssid, ssid, capture_filename, capture_duration)

if __name__ == "__main__":
    main()
