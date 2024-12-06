#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    // Check if the correct number of arguments is provided
    if (argc != 6) {
        printf("Usage: %s <interface> <channel> <bssid> <output_file> <duration>\n", argv[0]);
        return 1;
    }

    // Parse the command-line arguments
    const char *interface = argv[1];  // WiFi interface (e.g., wlan0)
    int channel = atoi(argv[2]);  // Channel to capture on
    const char *bssid = argv[3];  // BSSID of the target network
    const char *output_file = argv[4];  // Output pcap file name
    int duration = atoi(argv[5]);  // Duration to capture in seconds

    // Create the tshark command string
    char command[512];
    snprintf(command, sizeof(command),
             "tshark -i %s -c 1000 -w %s -b duration:%d -f \"ether host %s and type 0x888e\"",
             interface, output_file, duration, bssid);

    // Execute the command
    int result = system(command);
    
    if (result == 0) {
        printf("Packet capture complete. File saved to %s\n", output_file);
    } else {
        printf("Error occurred while capturing packets.\n");
    }

    return 0;
}
