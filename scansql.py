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
    try:
        action = form.attrs.get("action", "").lower()
    except KeyError:
        action = None
    
    # Get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    
    # Get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        
        # Skip inputs without a name attribute
        if input_name:
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
    
    # Put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    try:
        response_content = response.content.decode().lower()
    except UnicodeDecodeError:
        return False
    
    for error in errors:
        # If you find one of these errors, return True
        if error in response_content:
            return True
    # No error detected
    return False

def scan_sql_injection(url):
    # Test on URL (only append quotes to the parameters, not the base URL)
    for c in "\"'":
        # Check if the URL has query parameters
        if '?' in url:
            new_url = f"{url}{c}"
            print("[!] Trying", new_url)
            try:
                res = s.get(new_url)
                if is_vulnerable(res):
                    print("[+] SQL Injection vulnerability detected, link:", new_url)
                    return
            except requests.exceptions.RequestException as e:
                print(f"Error occurred: {e}")
                continue

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
                    # Any input form that is hidden or has some value,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # All others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            
            # Join the URL with the action (form request URL)
            action_url = urljoin(url, form_details["action"])
            try:
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
            except requests.exceptions.RequestException as e:
                print(f"Error occurred during form submission: {e}")
                continue

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan for SQL Injection vulnerabilities")
    
    args = parser.parse_args()
    url = args.url
    
    print(f"[*] Scanning {url} for SQL Injection vulnerabilities...")
    scan_sql_injection(url)

if __name__ == "__main__":
    main()
