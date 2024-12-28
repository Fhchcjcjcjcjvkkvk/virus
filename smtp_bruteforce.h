#ifndef SMTP_BRUTEFORCE_H
#define SMTP_BRUTEFORCE_H

#include <string>

bool initWinsock();
SOCKET connectToSMTPServer(const std::string &hostname, int port);
bool sendData(SOCKET sock, const std::string &data);
std::string receiveData(SOCKET sock);
bool bruteForceSMTP(const std::string &username, const std::string &password, const std::string &hostname, int port);

std::string base64Encode(const std::string &in);

#endif
