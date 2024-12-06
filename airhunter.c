#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMMAND_SIZE 512

int main() {
    char bssid[32];
    char filename[100];
    char command[COMMAND_SIZE];

    // Prompt the user to enter the BSSID
    printf("ENTER BSSID: ");
    scanf("%31s", bssid);

    // Prompt the user to enter the file name
    printf("ENTER SAVE FILE (e.g., capture.pcap): ");
    scanf("%99s", filename);

    // Construct the Tshark command
    snprintf(command, COMMAND_SIZE, 
             "tshark -i Wi-Fi -Y \"eapol && wlan.bssid == %s\" -w %s",
             bssid, filename);

    // Display the constructed command for verification
    printf("Executing command: %s\n", command);

    // Execute the command
    int result = system(command);

    // Check the result of the system call
    if (result == 0) {
        printf("Packet capture completed successfully and saved to %s\n", filename);
    } else {
        printf("Failed to execute the Tshark command. Please ensure Tshark is installed and accessible.\n");
    }

    return 0;
}
