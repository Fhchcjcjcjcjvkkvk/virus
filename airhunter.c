#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void capture_packets(const char *interface, const char *file_name, const char *bssid) {
    // Build the command to start tshark capture
    char command[512];
    snprintf(command, sizeof(command), "tshark -i %s -a duration:60 -w %s -f \"ether dst %s and eapol\"", interface, file_name, bssid);
    
    printf("Starting capture on interface %s, BSSID: %s\n", interface, bssid);
    
    // Run the capture command
    int result = system(command);
    
    if (result != 0) {
        fprintf(stderr, "Error running tshark capture.\n");
        return;
    }

    printf("Capture complete. EAPOL packets saved in %s.\n", file_name);
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s -w <output_file> -b <bssid> -i <interface>\n", argv[0]);
        return 1;
    }

    const char *output_file = NULL;
    const char *bssid = NULL;
    const char *interface = NULL;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0) {
            bssid = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0) {
            interface = argv[++i];
        }
    }

    if (output_file == NULL || bssid == NULL || interface == NULL) {
        fprintf(stderr, "Error: -w (output file), -b (bssid), and -i (interface) are required.\n");
        return 1;
    }

    // Start capturing packets
    capture_packets(interface, output_file, bssid);

    return 0;
}
