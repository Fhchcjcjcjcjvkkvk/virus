import socket
import sys
from colorama import Fore, init

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Function to check if an IP is reachable
def check_ip(ip, available_ips):
    try:
        # Try to resolve the IP to a valid socket
        socket.gethostbyaddr(ip)
        print(f"{Fore.GREEN}{ip} AVAILABLE!")
        available_ips.append(ip)  # Add to the list of available IPs
    except socket.herror:
        print(f"{Fore.RED}{ip} NOT EXISTING!")

# Main function to read IPs from the file and check each
def main():
    # Ensure we have the correct number of arguments
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <ips_file> <scan>")
        sys.exit(1)
    
    ips_file = sys.argv[1]

    # Try to open the file and read the IPs
    try:
        with open(ips_file, 'r') as file:
            ip_list = file.readlines()

        # Remove any trailing newline characters
        ip_list = [ip.strip() for ip in ip_list]

        # List to store available IPs
        available_ips = []

        # Iterate over each IP and check availability
        for ip in ip_list:
            check_ip(ip, available_ips)

        # Save available IPs to 'available.txt' if any
        if available_ips:
            with open("available.txt", "w") as f:
                for ip in available_ips:
                    f.write(f"{ip}\n")
            print(f"\n{Fore.GREEN}Available IPs have been saved to 'available.txt'.")
        else:
            print(f"{Fore.RED}No available IPs found.")

    except FileNotFoundError:
        print(f"{Fore.RED}Error: File '{ips_file}' not found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
