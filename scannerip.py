import socket
import sys
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# Function to check if the IP is reachable on a given port
def check_ip(ip, port=80, timeout=2):
    try:
        # Try to connect to the IP on the given port
        socket.setdefaulttimeout(timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))

        # If result is 0, it means the IP is reachable on that port
        if result == 0:
            return True
        else:
            return False
    except socket.error:
        return False
    finally:
        sock.close()

# Function to scan the IPs from a file and save available IPs to a new file
def scan_ips(file_name):
    available_ips = []  # List to store available IPs
    
    try:
        with open(file_name, 'r') as file:
            ips = file.readlines()

        for ip in ips:
            ip = ip.strip()  # Remove any surrounding whitespace
            if check_ip(ip):
                print(f"{Fore.GREEN}{ip} AVAILABLE!")
                available_ips.append(ip)  # Add to available IP list
            else:
                print(f"{Fore.RED}{ip} NOT EXISTING!")

        # Save the available IPs to 'available.txt'
        if available_ips:
            with open('available.txt', 'w') as f:
                for ip in available_ips:
                    f.write(ip + '\n')
            print(f"{Fore.CYAN}Available IPs have been saved to 'available.txt'.")
        else:
            print(f"{Fore.YELLOW}No available IPs found.")

    except FileNotFoundError:
        print(f"{Fore.YELLOW}Error: The file '{file_name}' was not found.")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.YELLOW}Usage: python scanner.py <ips.txt>")
        sys.exit(1)

    ips_file = sys.argv[1]
    scan_ips(ips_file)
