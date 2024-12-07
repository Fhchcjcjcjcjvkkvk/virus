#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CMD_LEN 256
#define MAX_OUTPUT_LEN 1024

// Function to run the tshark command and capture the output
void run_tshark(char *cmd, char *output) {
    FILE *fp;
    char buffer[MAX_OUTPUT_LEN];

    fp = _popen(cmd, "r");
    if (fp == NULL) {
        perror("Error running tshark");
        exit(1);
    }

    // Capture output from tshark
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        strcat(output, buffer);
    }

    fclose(fp);
}

// Function to parse the tshark output and display network information
void parse_tshark_output(char *output) {
    char *line = strtok(output, "\n");
    int beacon_count = 0;

    while (line != NULL) {
        char bssid[18], essid[33];
        
        // Search for a line containing the BSSID and ESSID
        if (sscanf(line, "BSSID: %17s ESSID: \"%32[^\"]\"", bssid, essid) == 2) {
            beacon_count++;  // Increment the beacon count for each packet
            printf("BSSID: %s\n", bssid);
            printf("ESSID: %s\n", essid);
            printf("Beacon Count: %d\n", beacon_count);
            printf("-------------------------\n");
        }

        line = strtok(NULL, "\n");
    }
}

int main() {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN] = "";

    // Command to run tshark and capture beacon frames
    // Ensure to replace "Wi-Fi" with the name of your network interface
    snprintf(cmd, sizeof(cmd), "tshark -i Wi-Fi -T fields -e wlan.bssid -e wlan.ssid -f \"type mgt subtype beacon\"");

    printf("Scanning for nearby networks...\n");

    // Run the tshark command and capture its output
    run_tshark(cmd, output);

    // Parse and display the results
    parse_tshark_output(output);

    return 0;
}
