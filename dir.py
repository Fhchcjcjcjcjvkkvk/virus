import os
import socket

HOST = 0.0.0.0
PORT = 12345

def handle_upload(connection, server_destination):
    file_name = connection.recv(1024).decode()
    file_size = int(connection.recv(1024).decode())

    with open(os.path.join(server_destination, file_name), 'wb') as f:
        remaining = file_size
        while remaining:
            data = connection.recv(min(1024, remaining))
            if not data:
                break
            f.write(data)
            remaining -= len(data)
    print(f"File {file_name} uploaded to {server_destination}.")

def handle_download(connection, server_destination):
    file_name = connection.recv(1024).decode()
    file_path = os.path.join(server_destination, file_name)

    if not os.path.exists(file_path):
        connection.send(b"ERROR: File not found!")
        return

    file_size = os.path.getsize(file_path)
    connection.send(str(file_size).encode())

    with open(file_path, 'rb') as f:
        while (data := f.read(1024)):
            connection.send(data)
    print(f"File {file_name} sent to client.")

def main():
    server_destination = 'server_files'
    os.makedirs(server_destination, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"Server listening on {HOST}:{PORT}...")

        while True:
            conn, addr = s.accept()
            print(f"Connected by {addr}")
            command = conn.recv(1024).decode()

            if command.startswith("upload"):
                handle_upload(conn, server_destination)
            elif command.startswith("download"):
                handle_download(conn, server_destination)
            else:
                print(f"Unknown command: {command}")
            conn.close()

if __name__ == "__main__":
    main()
