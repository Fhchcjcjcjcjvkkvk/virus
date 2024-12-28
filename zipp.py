import pyzipper

# Define the name of the ZIP file and the password
zip_filename = 'emptyfile.zip'
password = 'MerdeMerde2023+'

# Create an empty password-protected zip file
with pyzipper.AESZipFile(zip_filename, 'w', compression=pyzipper.ZIP_DEFLATED) as zipf:
    zipf.setpassword(password.encode())  # Set the password

print(f'Password-protected empty zip file "{zip_filename}" created successfully.')
