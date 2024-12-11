import zipfile
import argparse
from tqdm import tqdm

# Set up argument parsing for command-line usage
def parse_args():
    parser = argparse.ArgumentParser(description="Crack the password of a ZIP file using a wordlist.")
    parser.add_argument("zip_file", help="Path to the ZIP file to crack.")
    parser.add_argument("wordlist", help="Path to the wordlist (password list) file.")
    return parser.parse_args()

# Main function to crack the ZIP file password
def crack_zip_password(zip_file_path, wordlist_path):
    try:
        # Initialize the ZipFile object
        zip_file = zipfile.ZipFile(zip_file_path)
        
        # Count the number of words in the wordlist
        with open(wordlist_path, "r") as f:
            n_words = len(f.readlines())

        # Print the total number of passwords to try
        print("Total passwords to test:", n_words)

        # Try each word in the wordlist
        with open(wordlist_path, "r") as wordlist:
            for word in tqdm(wordlist, total=n_words, unit="word"):
                try:
                    # Attempt to extract with the current word as the password
                    zip_file.extractall(pwd=word.strip().encode())
                except:
                    continue
                else:
                    print("[+]KEY FOUND!:", word.strip())
                    return  # Exit the function once the password is found
        print("[!] Password not found, try other wordlist.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    # Parse the arguments from the command line
    args = parse_args()

    # Call the function to crack the ZIP password
    crack_zip_password(args.zip_file, args.wordlist)
