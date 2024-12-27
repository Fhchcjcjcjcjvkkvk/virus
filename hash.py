import hashlib
import argparse

def hash_password(password, hash_type):
    """Hash the password using the specified hash type."""
    if hash_type == 'md5':
        return hashlib.md5(password.encode('utf-8')).hexdigest()
    elif hash_type == 'sha1':
        return hashlib.sha1(password.encode('utf-8')).hexdigest()
    elif hash_type == 'sha256':
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    elif hash_type == 'sha512':
        return hashlib.sha512(password.encode('utf-8')).hexdigest()
    elif hash_type == 'blake2b':
        return hashlib.blake2b(password.encode('utf-8')).hexdigest()
    else:
        raise ValueError("Unsupported hash type")

def brute_force_hash(target_hash, wordlist_path, hash_type):
    """Brute-force the hash using a wordlist."""
    try:
        with open(wordlist_path, 'r') as wordlist:
            for line in wordlist:
                word = line.strip()
                hashed_word = hash_password(word, hash_type)
                if hashed_word == target_hash:
                    return word
        return None
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist_path}' not found.")
        return None

def main():
    parser = argparse.ArgumentParser(description="Brute-force hash cracker")
    parser.add_argument("hash", help="The hash you want to crack")
    parser.add_argument("-P", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-t", "--hash-type", choices=['md5', 'sha1', 'sha256', 'sha512', 'blake2b'], default='md5', help="Hash type (default: md5)")

    args = parser.parse_args()

    result = brute_force_hash(args.hash, args.wordlist, args.hash_type)

    if result:
        print(f"KEY FOUND: [{result}]")
    else:
        print("KEY NOT FOUND")

if __name__ == "__main__":
    main()
