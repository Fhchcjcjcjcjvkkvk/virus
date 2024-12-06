#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMMAND_MAX 512

// Function prototypes
void show_networks();
void capture_eapol(const char *filename, const char *bssid);

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // Show networks if no arguments are provided
        show_networks();
    } else if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0) {
        // Capture EAPOL packets if the correct arguments are provided
        const char *filename = argv[2];
        const char *bssid = argv[4];
        capture_eapol(filename, bssid);
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  airhunter              - Show available networks\n");
        fprintf(stderr, "  airhunter -w <file> -b <BSSID> - Capture EAPOL packets\n");
        return 1;
    }

    return 0;
}

// Function to display available networks
void show_networks() {
    char command[COMMAND_MAX];

    // Use tshark to capture beacon frames and display network information
    snprintf(command, sizeof(command), 
             "tshark -i Wi-Fi -Y \"wlan.fc.type_subtype == 8\" -T fields -e wlan.sa -e wlan.ssid -e wlan_rsna_eapol.keydes.keymic -e wlan_mgt.fixed.beacon\" 2>nul");

    printf("Scanning for networks...\n\n");
    system(command);
}

// Function to capture EAPOL packets for a specific BSSID
void capture_eapol(const char *filename, const char *bssid) {
    char command[COMMAND_MAX];

    printf("Capturing EAPOL packets for BSSID %s and saving to %s...\n", bssid, filename);

    // Use tshark to filter EAPOL packets for the specified BSSID and save to a file
    snprintf(command, sizeof(command), 
             "tshark -i Wi-Fi -Y \"eapol && wlan.sa == %s\" -w %s 2>nul", 
             bssid, filename);

    int result = system(command);

    if (result == 0) {
        printf("Capture complete. Check the file %s.\n", filename);
    } else {
        fprintf(stderr, "Error: Failed to capture EAPOL packets. Ensure tshark is installed and the Wi-Fi interface is available.\n");
    }
}
