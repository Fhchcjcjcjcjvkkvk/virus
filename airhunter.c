#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void capture_eapol_packets(const char *output_file, const char *bssid) {
    char command[1024];
    
    // Set the interface name to "Wi-Fi" (or the appropriate interface on your system)
    snprintf(command, sizeof(command), "tshark -i \"Wi-Fi\" -a duration:30 -w %s -Y \"eapol && wlan.bssid == %s\"", output_file, bssid);

    // Print the command that is being run for debugging purposes
    printf("Running capture with command: %s\n", command);

    // Execute the tshark command using system()
    int result = system(command);

    if (result == 0) {
        printf("Capture finished successfully. The packets have been saved to %s\n", output_file);
    } else {
        printf("An error occurred while running tshark.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s -w <output.pcap> -b <BSSID>\n", argv[0]);
        return 1;
    }

    const char *output_file = NULL;
    const char *bssid = NULL;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0) {
            output_file = argv[i + 1];
        } else if (strcmp(argv[i], "-b") == 0) {
            bssid = argv[i + 1];
        }
    }

    // Validate input arguments
    if (output_file == NULL || bssid == NULL) {
        printf("Invalid arguments! Ensure you provide -w for output and -b for BSSID.\n");
        return 1;
    }

    // Call the function to capture EAPOL packets
    capture_eapol_packets(output_file, bssid);

    return 0;
}
