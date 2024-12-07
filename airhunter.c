#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INTERFACE_INDEX 1  // Set this to the correct index for "Wi-Fi" from tshark -D
#define COMMAND "tshark -i %d -T fields -e wlan.bssid -e wlan.ssid -e radiotap.dbm_antsignal -Y 'wlan.fc.type_subtype == 0x08'"

// Function to run tshark command and print the output
void capture_networks() {
    FILE *fp;
    char output[1024];
    char command[256];

    // Build the tshark command dynamically based on the interface index
    snprintf(command, sizeof(command), COMMAND, INTERFACE_INDEX);

    // Run tshark to capture BSSID, ESSID, and signal strength
    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to run tshark command");
        exit(1);
    }

    // Read and display the output
    printf("BSSID            ESSID              Signal Strength (dBm)\n");
    printf("----------------------------------------------------------\n");

    while (fgets(output, sizeof(output), fp) != NULL) {
        // Clean the output line
        output[strcspn(output, "\n")] = 0;  // Remove newline character
        
        // Display captured data
        printf("%s\n", output);
    }

    fclose(fp);
}

int main() {
    capture_networks();
    return 0;
}
