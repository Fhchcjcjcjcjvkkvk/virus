import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
import argparse

# Initialize an HTTP session & set the browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # Get the form action (target URL)
    action = form.attrs.get("action", None)
    if action:
        action = action.lower()

    # Get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()

    # Get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    # Put everything in the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    """A simple boolean function that determines whether a page is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    if response.status_code != 200:
        return False  # Non-200 status codes are unlikely to indicate SQLi

    # Look for SQLi-related error messages in the response content
    for error in errors:
        if error in response.content.decode().lower():
            return True

    # No error detected
    return False

def scan_sql_injection(url):
    # Test on URL
    for c in "\"'":
        # Add quote/double quote character to the URL
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        # Make the HTTP request
        res = s.get(new_url)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself, no need to proceed for extracting forms
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            return

    # Test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # The data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    # Any input form that is hidden or has some value, just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # All others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            
            # Join the URL with the action (form request URL)
            action_url = urljoin(url, form_details["action"])  # Use `action_url` instead of overwriting `url`

            if form_details["method"] == "post":
                res = s.post(action_url, data=data)
            elif form_details["method"] == "get":
                res = s.get(action_url, params=data)

            # Test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", action_url)
                print("[+] Form:")
                pprint(form_details)
                break

def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument('-u', '--url', required=True, help="URL to scan for SQL Injection vulnerabilities")
    args = parser.parse_args()

    # Run the scan with the given URL
    scan_sql_injection(args.url)

if __name__ == "__main__":
    main()
