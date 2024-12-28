#include <stdio.h>
#include <libssh/libssh.h>
#include <stdlib.h>

#define HOST "your_remote_host"
#define USER "your_username"
#define PASSWORD "your_password"

int main() {
    ssh_session session;
    int rc;

    // Create SSH session
    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        return -1;
    }

    // Set the session options
    ssh_options_set(session, SSH_OPTIONS_HOST, HOST);
    ssh_options_set(session, SSH_OPTIONS_USER, USER);

    // Connect to the remote host
    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to host: %s\n", ssh_get_error(session));
        ssh_free(session);
        return -1;
    }

    // Authenticate using a password
    rc = ssh_userauth_password(session, NULL, PASSWORD);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    printf("Connection and authentication successful!\n");

    // Disconnect and free the session
    ssh_disconnect(session);
    ssh_free(session);

    return 0;
}
