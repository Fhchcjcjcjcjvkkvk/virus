#include <libssh/libssh.h>
#include <iostream>

int main() {
    ssh_session my_ssh_session = ssh_new();
    if (my_ssh_session == NULL) {
        std::cerr << "Error creating SSH session." << std::endl;
        return 1;
    }

    // Setup SSH session here (connect, authenticate, etc.)
    // Example:
    // ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "hostname");

    std::cout << "libssh setup successfully!" << std::endl;

    ssh_free(my_ssh_session);
    return 0;
}
