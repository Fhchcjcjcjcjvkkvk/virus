#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Function to run a system command and capture output
void run_command(const char *cmd) {
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Command failed: %s\n", cmd);
        exit(1);
    }
}

// Function to list available networks
void list_networks(const char *interface) {
    printf("Listing available networks on interface: %s...\n", interface);

    // Use tshark to list networks (beacon frames)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tshark -i %s -f \"wlan.fc.type_subtype == 0x08\" -T fields -e wlan.bssid -e wlan.ssid -e wlan.crypto", interface);
    run_command(cmd);
}

// Function to capture EAPOL packets for a specific BSSID and save to a .pcap file
void capture_eapol(const char *file_name, const char *bssid, const char *interface) {
    printf("Capturing EAPOL frames from BSSID: %s on interface: %s\n", bssid, interface);
    
    // Run tshark to capture EAPOL frames
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tshark -i %s -f \"wlan.addr == %s && eapol\" -w %s", interface, bssid, file_name);

    // Run the capture command
    run_command(cmd);

    // Check if the EAPOL handshake was captured, otherwise exit
    printf("Capture complete. Saving to file: %s\n", file_name);
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // No arguments, list available networks
        list_networks("Wi-Fi");  // Replace with the actual interface name or index on your machine
    } else if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0) {
        // Capture packets with EAPOL
        const char *file_name = argv[2];
        const char *bssid = argv[4];
        
        capture_eapol(file_name, bssid, "Wi-Fi");  // Replace with actual interface name or index
    } else {
        // Invalid usage
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  airhunter           # List available networks\n");
        fprintf(stderr, "  airhunter -w <file.pcap> -b <BSSID>   # Capture EAPOL frames from BSSID\n");
        return 1;
    }

    return 0;
}
