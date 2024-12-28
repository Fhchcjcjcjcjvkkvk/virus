#ifndef MEPHISTO_H
#define MEPHISTO_H

#include <string>
#include <iostream>

bool smtpConnectAndAuthenticate(const std::string &server, int port, const std::string &username, const std::string &password);
std::string base64_encode(const std::string &in);

#endif // MEPHISTO_H
