import zipfile
import argparse

def crack_zip(zip_file, password_file):
    try:
        with open(password_file, 'r') as file:
            passwords = file.readlines()

        with zipfile.ZipFile(zip_file, 'r') as zip:
            for password in passwords:
                password = password.strip()  # Remove any extra whitespace
                try:
                    zip.setpassword(password.encode('utf-8'))
                    zip.testzip()  # Test if the password works
                    print(f"KEY FOUND: {password}")
                    return
                except RuntimeError:
                    continue  # Password incorrect, try next one

        print("KEY NOT FOUND")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Crack a ZIP file password using a brute-force approach.")
    parser.add_argument('zipfile', help="The path to the ZIP file.")
    parser.add_argument('passwordfile', help="The path to the password file containing a list of possible passwords.")
    args = parser.parse_args()

    crack_zip(args.zipfile, args.passwordfile)

if __name__ == "__main__":
    main()
