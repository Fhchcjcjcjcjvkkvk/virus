#include "libssh.h"
#include <iostream>

int main() {
    ssh_session my_ssh_session;
    int rc;

    // Initialize SSH session
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL) {
        std::cerr << "Error creating SSH session." << std::endl;
        return -1;
    }

    // Set server parameters
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "your_ssh_server_address");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "your_ssh_username");

    // Connect to the SSH server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        std::cerr << "Error connecting to server: " << ssh_get_error(my_ssh_session) << std::endl;
        ssh_free(my_ssh_session);
        return -1;
    }

    // Authenticate with password
    rc = ssh_userauth_password(my_ssh_session, NULL, "your_ssh_password");
    if (rc != SSH_AUTH_SUCCESS) {
        std::cerr << "Authentication failed: " << ssh_get_error(my_ssh_session) << std::endl;
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        return -1;
    }

    // Execute a command
    ssh_channel channel = ssh_channel_new(my_ssh_session);
    if (channel == NULL) {
        std::cerr << "Error creating channel." << std::endl;
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        return -1;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        std::cerr << "Error opening channel: " << ssh_get_error(my_ssh_session) << std::endl;
        ssh_channel_free(channel);
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        return -1;
    }

    rc = ssh_channel_request_exec(channel, "ls -l");
    if (rc != SSH_OK) {
        std::cerr << "Error requesting command execution: " << ssh_get_error(my_ssh_session) << std::endl;
        ssh_channel_free(channel);
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        return -1;
    }

    // Read the output of the command
    char buffer[256];
    while (true) {
        rc = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
        if (rc == SSH_ERROR) {
            std::cerr << "Error reading from channel: " << ssh_get_error(my_ssh_session) << std::endl;
            break;
        }
        if (rc == 0) {
            break; // EOF
        }

        buffer[rc] = '\0'; // Null-terminate the string
        std::cout << buffer;
    }

    // Clean up
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);

    return 0;
}
