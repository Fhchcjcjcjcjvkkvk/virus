#include <winsock2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define FTP_PORT 21
#define BUFFER_SIZE 1024

void send_response(SOCKET client_socket, const char *response) {
    send(client_socket, response, strlen(response), 0);
}

void handle_client(SOCKET client_socket) {
    char buffer[BUFFER_SIZE];

    // Send FTP greeting message
    send_response(client_socket, "220 Welcome to Simple FTP Server\r\n");

    // Handle client commands (USER, QUIT)
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            break;  // Client disconnected or error
        }

        // Print the command received
        printf("Received: %s", buffer);

        // Simple response for USER command
        if (strncmp(buffer, "USER", 4) == 0) {
            send_response(client_socket, "331 Username okay, need password\r\n");
        }
        // Simple response for QUIT command
        else if (strncmp(buffer, "QUIT", 4) == 0) {
            send_response(client_socket, "221 Goodbye\r\n");
            break;
        }
        // Default response for unknown commands
        else {
            send_response(client_socket, "502 Command not implemented\r\n");
        }
    }

    // Close the connection with the client
    closesocket(client_socket);
}

int main() {
    WSADATA wsaData;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // Create the server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    // Set up the server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(FTP_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces

    // Bind the socket to the address and port
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed\n");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    // Start listening for incoming connections
    if (listen(server_socket, 5) == SOCKET_ERROR) {
        printf("Listen failed\n");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    printf("FTP Server is running on port %d...\n", FTP_PORT);

    // Accept and handle client connections
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed\n");
            continue;
        }

        printf("Client connected\n");

        // Handle client communication
        handle_client(client_socket);
    }

    // Clean up
    closesocket(server_socket);
    WSACleanup();
    return 0;
}
