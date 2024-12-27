import pyzipper
import sys
import argparse
import os  # Import os to check if the file exists

def zip_bruteforce(zip_file, password_file):
    # Check if the zip file exists
    if not os.path.isfile(zip_file):
        print(f"NO ZIP FILE NAMED {zip_file} FOUND!")
        sys.exit(1)

    # Open the password file
    try:
        with open(password_file, 'r') as file:
            passwords = file.readlines()
    except FileNotFoundError:
        print(f"Password file '{password_file}' not found.")
        sys.exit(1)

    # Try each password in the file
    with pyzipper.AESZipFile(zip_file) as zf:
        for password in passwords:
            password = password.strip()  # Remove any trailing newline or space
            try:
                # Attempt to extract the first file in the zip
                zf.setpassword(password.encode())
                zf.testzip()  # Test if the password works
                print(f"KEY FOUND: [{password}]")
                return password
            except RuntimeError:
                # Password is incorrect, continue with next one
                pass
    
    print("KEY NOT FOUND")
    return None

def main():
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="Brute-force a password protected ZIP file using a list of passwords.")
    
    # Define command-line arguments
    parser.add_argument("zip_file", help="The path to the ZIP file to crack.")
    parser.add_argument("-P", "--password_file", required=True, help="The path to the file containing a list of passwords.")
    
    # Parse the arguments
    args = parser.parse_args()

    # Call the zip_bruteforce function
    zip_bruteforce(args.zip_file, args.password_file)

if __name__ == '__main__':
    main()
