#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMMAND_SIZE 512

int main() {
    char bssid[32];
    char filename[100];
    char interface[50];
    char command[COMMAND_SIZE];

    // Prompt the user to enter the Wi-Fi interface
    printf("ENTER Wi-Fi INTERFACE (e.g., Wi-Fi or 3): ");
    scanf("%49s", interface);

    // Prompt the user to enter the BSSID
    printf("ENTER BSSID: ");
    scanf("%31s", bssid);

    // Prompt the user to enter the output file name
    printf("ENTER SAVE FILE (e.g., capture.pcapng): ");
    scanf("%99s", filename);

    // Construct the dumpcap command
    snprintf(command, COMMAND_SIZE,
             "dumpcap -i %s -f \"ether proto 0x888e and wlan bssid %s\" -w %s",
             interface, bssid, filename);

    // Display the constructed command
    printf("Executing command: %s\n", command);

    // Execute the command
    int result = system(command);

    // Check the result
    if (result == 0) {
        printf("Packet capture completed successfully and saved to %s\n", filename);
    } else {
        printf("Failed to execute the dumpcap command. Please ensure dumpcap is installed and accessible.\n");
    }

    return 0;
}
