import PyPDF2

def pdf_cracker(pdf_file, password_list):
    """
    Attempts to unlock a PDF file using a password list.
    
    :param pdf_file: Path to the encrypted PDF file.
    :param password_list: Path to the file containing passwords (one per line).
    """
    try:
        # Open the PDF file
        with open(pdf_file, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)

            if not pdf_reader.is_encrypted:
                print(f"{pdf_file} is not password protected.")
                return

            # Read the password list
            with open(password_list, 'r') as passwords:
                for password in passwords:
                    password = password.strip()
                    try:
                        # Attempt to decrypt the PDF
                        if pdf_reader.decrypt(password):
                            print(f"KEY FOUND: [{password}]")
                            return
                    except Exception as e:
                        pass

            print("KEY NOT FOUND")
    except FileNotFoundError:
        print(f"File not found: {pdf_file} or {password_list}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PDF Cracker Tool for Educational Use")
    parser.add_argument("pdf_file", help="Path to the encrypted PDF file")
    parser.add_argument("-P", "--passwords", required=True, help="Path to the password list file")

    args = parser.parse_args()

    try:
        pdf_cracker(args.pdf_file, args.passwords)
    except KeyboardInterrupt:
        print("\nQuitting mephisto...")
