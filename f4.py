import requests
import argparse
from urllib.parse import urlparse

# Function to check if a website is vulnerable to clickjacking
def check_clickjacking(url):
    try:
        # Parse the URL to ensure it includes a scheme
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'https://' + url  # Default to HTTPS if no scheme provided
        
        # Send a GET request to the URL
        response = requests.get(url)
        
        # Check if the status code is OK (200)
        if response.status_code != 200:
            print(f"[-] Error: Received status code {response.status_code} for {url}")
            return False
        
        headers = response.headers
        
        # Check for the presence of the X-Frame-Options header
        if 'X-Frame-Options' not in headers:
            return True
        
        # Get the value of X-Frame-Options and check it
        x_frame_options = headers['X-Frame-Options'].lower()
        if x_frame_options != 'deny' and x_frame_options != 'sameorigin':
            return True
        
        return False
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while checking {url}: {e}")
        return False

# Main function to parse arguments and check the URL
def main():
    parser = argparse.ArgumentParser(description='Clickjacking Vulnerability Scanner')
    parser.add_argument('url', type=str, help='The URL of the website to check')
    parser.add_argument('-l', '--log', action='store_true', help='Print out the response headers for analysis')
    args = parser.parse_args()
    url = args.url
    
    # Check if the URL is vulnerable
    is_vulnerable = check_clickjacking(url)
    
    if is_vulnerable:
        print(f"[+] {url} may be vulnerable to clickjacking.")
    else:
        print(f"[-] {url} is not vulnerable to clickjacking.")
    
    # If --log option is provided, print response headers
    if args.log:
        # Again, ensure URL has scheme (https://)
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'https://' + url
        
        try:
            response = requests.get(url)
            print("\nResponse Headers:")
            for header, value in response.headers.items():
                print(f"{header}: {value}")
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while fetching headers for {url}: {e}")

if __name__ == '__main__':
    main()
