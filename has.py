import hashlib

# Hash the word "password1" using SHA-256
hashed_password = hashlib.sha256("password1".encode()).hexdigest()
print(hashed_password)
