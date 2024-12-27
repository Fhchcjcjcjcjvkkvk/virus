import pyzipper

def create_protected_zip(zip_filename, file_to_zip, password):
    with pyzipper.AESZipFile(zip_filename, mode='w', encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        zf.write(file_to_zip)

if __name__ == '__main__':
    # Create a sample text file to zip
    file_name = '0.py'
    with open(file_name, 'w') as f:
        f.write("This is a test file for password protection.")

    # Create a password-protected ZIP file
    zip_filename = 'protected.zip'
    password = 'password1'
    create_protected_zip(zip_filename, file_name, password)

    print(f"Created password-protected ZIP file: {zip_filename}")
