import os
import sys
import zipfile
import pyzipper
import argparse
from datetime import datetime
import time

# Brute force for ZIP file
def brute_force_zip(zip_file_path, wordlist_path, extraction_path):
    failed_attempts = []  # List to store failed attempts for one line of output
    
    # Open the ZIP file using pyzipper (supports AES-encrypted ZIPs)
    with pyzipper.AESZipFile(zip_file_path) as zf:
        # Open the wordlist file to iterate over each password
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist_file:
            # Loop through each line in the wordlist
            for line in wordlist_file:
                password_str = line.strip()  # Remove any leading/trailing whitespace (e.g., newlines)
                
                try:
                    # Set the password for the ZIP file
                    zf.pwd = password_str.encode('utf-8')
                    
                    # Try extracting the contents of the ZIP file
                    zf.extractall(path=extraction_path)
                    
                    # If successful, print and return the password
                    print(f"Password found: {password_str}")
                    return password_str
                
                except RuntimeError:
                    # If extraction fails, the password is incorrect
                    failed_attempts.append(password_str)  # Append failed attempt to the list
                    continue
                except Exception as e:
                    # If there are other errors, print them and continue
                    print(f"Error for: {password_str}, Error: {e}")
                    continue

    # After all attempts, print all failed attempts in a single line
    if failed_attempts:
        print(f"Attempt Failed: {' '.join(failed_attempts)}")  # Join all failed attempts into one line
    else:
        print("Password not found in the wordlist")

# Main execution logic for ZIP cracking with argparse
if __name__ == "__main__":
    # Set up argument parsing for the ZIP file cracking functionality
    parser = argparse.ArgumentParser(description="Crack a ZIP file password using a wordlist.")
    parser.add_argument('-z', '--zip', type=str, help="Path to the ZIP file", required=True)
    parser.add_argument('wordlist', type=str, help="Path to the wordlist file")
    parser.add_argument('-e', '--extract', type=str, help="Path to extract the ZIP file contents", required=True)

    args = parser.parse_args()

    # Ensure the wordlist exists
    if not os.path.exists(args.wordlist):
        print(f"Error: Wordlist file '{args.wordlist}' not found.")
        sys.exit(1)

    # Ensure the ZIP file exists
    if not os.path.exists(args.zip):
        print(f"Error: ZIP file '{args.zip}' not found.")
        sys.exit(1)

    # Ensure the extraction path exists
    if not os.path.exists(args.extract):
        print(f"Error: Extraction path '{args.extract}' does not exist.")
        sys.exit(1)

    # Perform the ZIP cracking
    print("\n[+] Cracking ZIP file password...")
    brute_force_zip(args.zip, args.wordlist, args.extract)
