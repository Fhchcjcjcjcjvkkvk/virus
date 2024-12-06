#include <stdio.h>
#include <stdlib.h>

int main() {
    char command[512];

    // Construct the command to execute tshark
    // -i <interface>: Specify the interface (e.g., wlan0, Wi-Fi)
    // -I: Enable monitor mode
    // -Y: Filter to show Wi-Fi beacons and probe requests
    // -T fields: Output specific fields
    // -e: Specify the fields (SSID, BSSID, Signal strength)
    snprintf(command, sizeof(command),
             "tshark -i Wi-Fi -I -Y \"wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x04\" "
             "-T fields -e wlan.sa -e wlan.ssid -e radiotap.dbm_antsignal");

    printf("Running command:\n%s\n\n", command);

    // Execute the tshark command
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to run tshark");
        return 1;
    }

    // Read and display the output from tshark
    char buffer[1024];
    printf("Detected Wi-Fi Networks and Stations:\n");
    printf("BSSID                | SSID                    | Signal Strength (dBm)\n");
    printf("------------------------------------------------------------------------\n");

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Parse and display the output
        printf("%s", buffer);
    }

    // Close the pipe
    pclose(fp);

    return 0;
}
