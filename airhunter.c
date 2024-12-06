#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void capture_packets(const char *output_file, const char *bssid, int channel) {
    char command[512];

    // Set the channel for the wireless interface (this command may need admin privileges)
    char channel_command[128];
    snprintf(channel_command, sizeof(channel_command), 
             "netsh wlan set hostednetwork channel=%d", channel);
    system(channel_command);

    // Construct the tshark command to capture EAPOL packets on the specified BSSID and channel
    snprintf(command, sizeof(command), 
             "tshark -i \"Wi-Fi\" -f \"eapol and ether host %s\" -c 10000 -w %s", 
             bssid, output_file);

    // Run the tshark command to capture packets
    int result = system(command);
    if (result == -1) {
        perror("Error executing tshark");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s --write <output_file> --bssid <bssid> --channel <channel>\n", argv[0]);
        return 1;
    }

    const char *output_file = NULL;
    const char *bssid = NULL;
    int channel = -1;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--write") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--bssid") == 0 && i + 1 < argc) {
            bssid = argv[++i];
        } else if (strcmp(argv[i], "--channel") == 0 && i + 1 < argc) {
            channel = atoi(argv[++i]);
        }
    }

    if (output_file == NULL || bssid == NULL || channel == -1) {
        fprintf(stderr, "Invalid arguments! Usage: %s --write <output_file> --bssid <bssid> --channel <channel>\n", argv[0]);
        return 1;
    }

    // Start packet capture
    printf("Starting packet capture...\n");
    capture_packets(output_file, bssid, channel);
    printf("Capture complete. Packets saved to %s\n", output_file);

    return 0;
}
