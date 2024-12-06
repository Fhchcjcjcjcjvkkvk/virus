#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CMD_LENGTH 256

void capture_packets(const char *interface, const char *bssid, const char *output_file) {
    char cmd[MAX_CMD_LENGTH];
    
    // Build the tshark command to capture EAPOL packets and filter by BSSID
    snprintf(cmd, MAX_CMD_LENGTH, "tshark -i \"%s\" -Y \"eapol && wlan.bssid == %s\" -w \"%s\" -a duration:30", 
            interface, bssid, output_file);
    
    printf("Running command: %s\n", cmd);
    
    // Execute the command
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Error running tshark");
        exit(1);
    }
    
    char buffer[256];
    int eapol_found = 0;

    // Check if EAPOL packets are captured
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "EAPOL")) {
            eapol_found = 1;
            break;
        }
    }

    fclose(fp);

    if (!eapol_found) {
        printf("No EAPOL packets found, stopping capture...\n");
        exit(0); // Exit if no EAPOL packets are found
    }
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s -w <output_file> -b <bssid>\n", argv[0]);
        return 1;
    }

    const char *output_file = NULL;
    const char *bssid = NULL;
    
    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bssid = argv[++i];
        }
    }

    if (output_file == NULL || bssid == NULL) {
        printf("Missing required arguments: -w (output file) and -b (BSSID)\n");
        return 1;
    }

    // Interface name for Windows (change this to the correct interface name)
    const char *interface = "Wi-Fi"; // change to your actual interface name on Windows

    capture_packets(interface, bssid, output_file);
    
    return 0;
}
