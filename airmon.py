import argparse
import os
import subprocess
import urllib.request
import zipfile
import tempfile

NPCAP_URL = "https://nmap.org/npcap/dist/npcap-1.70.exe"

def download_and_install_npcap():
    # Download npcap installer
    print("Downloading npcap...")
    installer_path = os.path.join(tempfile.gettempdir(), "npcap-1.70.exe")
    urllib.request.urlretrieve(NPCAP_URL, installer_path)
    print("Installing npcap...")
    # Install npcap silently
    subprocess.run([installer_path, '/S'], check=True)
    # Add npcap to system PATH
    npcap_path = r"C:\Program Files\Npcap"
    if npcap_path not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + npcap_path
        print("Npcap installed and added to PATH.")
    else:
        print("Npcap is already in PATH.")

def list_adapters():
    # This function lists all network adapters that support monitor mode
    print("Listing compatible adapters that support monitor mode:")
    result = subprocess.run(['npcap', '-WiFi'], capture_output=True, text=True)
    print(result.stdout)

def enable_monitor_mode(adapter_name):
    # This function enables monitor mode on the selected adapter
    print(f"Enabling monitor mode on adapter: {adapter_name}")
    result = subprocess.run(['npcap', '-i', adapter_name, '--set', 'monitor-mode', '1'], capture_output=True, text=True)
    if result.returncode == 0:
        print("Monitor Mode enabled!")
    else:
        print(f"Failed to enable monitor mode: {result.stderr}")

def disable_monitor_mode(adapter_name):
    # This function disables monitor mode on the selected adapter
    print(f"Disabling monitor mode on adapter: {adapter_name}")
    result = subprocess.run(['npcap', '-i', adapter_name, '--set', 'monitor-mode', '0'], capture_output=True, text=True)
    if result.returncode == 0:
        print("Monitor Mode disabled!")
    else:
        print(f"Failed to disable monitor mode: {result.stderr}")

def main():
    parser = argparse.ArgumentParser(description="Manage monitor mode on WiFi adapters using npcap.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    start_parser = subparsers.add_parser('start', help='Enable monitor mode on a selected adapter')
    start_parser.add_argument('adapter', type=str, help='The name of the adapter to set to monitor mode')

    kill_parser = subparsers.add_parser('kill', help='Disable monitor mode on a selected adapter')
    kill_parser.add_argument('adapter', type=str, help='The name of the adapter to disable monitor mode')

    args = parser.parse_args()

    # Check if npcap is installed, if not download and install it
    try:
        subprocess.run(['npcap', '-v'], check=True, capture_output=True)
    except FileNotFoundError:
        download_and_install_npcap()

    if args.command == 'start':
        list_adapters()
        enable_monitor_mode(args.adapter)
    elif args.command == 'kill':
        disable_monitor_mode(args.adapter)

if __name__ == '__main__':
    main()
