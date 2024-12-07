#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CMD_LEN 256
#define MAX_OUTPUT_LEN 1024

// Function to run the tshark command and capture the output
void run_tshark(char *cmd, char *output) {
    FILE *fp;
    char buffer[MAX_OUTPUT_LEN];

    // Open the command for reading
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

    while (line != NULL) {
        char bssid[18], essid[33], beacon_count[10], live_time[20];

        // Search for a line containing the BSSID, ESSID, and other information
        if (sscanf(line, "BSSID: %17s ESSID: \"%32[^\"]\" Beacon count: %9s Live time: %19s", 
                    bssid, essid, beacon_count, live_time) == 4) {
            printf("BSSID: %s\n", bssid);
            printf("ESSID: %s\n", essid);
            printf("Beacon Count: %s\n", beacon_count);
            printf("Live Time: %s\n", live_time);
            printf("-------------------------\n");
        }

        line = strtok(NULL, "\n");
    }
}

int main() {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN] = "";

    // Command to run tshark and capture beacon frames on Windows
    // Ensure to replace "Wi-Fi" with the name of your network interface
    snprintf(cmd, sizeof(cmd), "tshark -i Wi-Fi -T fields -e wlan.bssid -e wlan.ssid -e wlan_beacon.beacon_count -e frame.time -f \"type mgt subtype beacon\"");

    printf("Scanning for nearby networks...\n");

    // Run the tshark command and capture its output
    run_tshark(cmd, output);

    // Parse and display the results
    parse_tshark_output(output);

    return 0;
}
