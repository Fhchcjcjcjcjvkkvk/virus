import pyzipper
import sys
import argparse

def crack_zip(zip_file, password_file):
    try:
        with pyzipper.AESZipFile(zip_file) as zf:
            with open(password_file, 'r', encoding='utf-8') as pf:
                for line in pf:
                    password = line.strip()  # Remove whitespace characters
                    try:
                        zf.pwd = password.encode('utf-8')
                        zf.testzip()  # Test if the password works
                        print(f"KEY FOUND: {password}")
                        return
                    except (RuntimeError, pyzipper.BadZipFile):
                        continue
        print("KEY NOT FOUND")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brute force a ZIP file password.")
    parser.add_argument("zip_file", help="The path to the ZIP file.")
    parser.add_argument("password_file", help="The path to the password list file.")
    args = parser.parse_args()

    crack_zip(args.zip_file, args.password_file)
