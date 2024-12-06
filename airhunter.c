#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CMD_LENGTH 256

void capture_packets(const char *interface, const char *bssid, const char *output_file) {
    char cmd[MAX_CMD_LENGTH];
    
    // Step 1: Capture all packets (no display filter during capture)
    snprintf(cmd, MAX_CMD_LENGTH, "tshark -i \"%s\" -w \"%s\" -a duration:30", 
            interface, output_file);
    
    printf("Running command: %s\n", cmd);
    
    // Execute the capture command
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Error running tshark");
        exit(1);
    }
    fclose(fp);

    // Step 2: Filter captured packets for EAPOL and the specified BSSID
    char filtered_cmd[MAX_CMD_LENGTH];
    snprintf(filtered_cmd, MAX_CMD_LENGTH, "tshark -r \"%s\" -Y \"eapol && wlan.bssid == %s\" -w \"%s\"", 
            output_file, bssid, output_file);
    
    printf("Running command: %s\n", filtered_cmd);
    
    // Execute the filtering command
    fp = popen(filtered_cmd, "r");
    if (fp == NULL) {
        perror("Error running tshark filtering command");
        exit(1);
    }
    
    char buffer[256];
    int eapol_found = 0;

    // Check if EAPOL packets are found in the filtered output
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "EAPOL")) {
            eapol_found = 1;
            break;
        }
    }

    fclose(fp);

    if (!eapol_found) {
        printf("No EAPOL packets found, stopping capture...\n");
        remove(output_file); // Remove the capture file if no EAPOL packets are found
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
