#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void show_usage() {
    printf("Usage: airhunter [-w <file.pcap>] [-b <BSSID>] [-i <interface>]\n");
    printf("  -w <file.pcap>  Write captured packets to a file\n");
    printf("  -b <BSSID>      Capture packets from a specific BSSID\n");
    printf("  -i <interface>  Specify the Wi-Fi interface (e.g., Wi-Fi)\n");
}

void list_networks() {
    // Use tshark to list available interfaces
    printf("Listing available interfaces...\n");
    system("tshark -D");

    // You can also list networks with netsh on Windows
    printf("Listing available Wi-Fi networks...\n");
    system("netsh wlan show networks mode=Bssid");
}

void capture_packets(const char *interface, const char *bssid, const char *file) {
    // Create the command to capture EAPOL packets with tshark
    char cmd[512];

    if (bssid != NULL) {
        // Capture packets from the specific BSSID
        snprintf(cmd, sizeof(cmd), "tshark -i \"%s\" -Y \"eapol\" -w %s -b 78:%s", interface, file, bssid);
    } else {
        // Capture all EAPOL packets (no BSSID filter)
        snprintf(cmd, sizeof(cmd), "tshark -i \"%s\" -Y \"eapol\" -w %s", interface, file);
    }

    printf("Capturing packets with command: %s\n", cmd);
    system(cmd);

    // Notify the user the capture is finished
    printf("Capture complete. Packets saved to %s\n", file);
}

int main(int argc, char **argv) {
    int opt;
    const char *interface = "Wi-Fi"; // Default Wi-Fi interface name
    const char *file = NULL;
    const char *bssid = NULL;

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "w:b:i:")) != -1) {
        switch (opt) {
            case 'w':
                file = optarg; // Output pcap file
                break;
            case 'b':
                bssid = optarg; // BSSID for specific capture
                break;
            case 'i':
                interface = optarg; // Wi-Fi interface
                break;
            default:
                show_usage();
                return 1;
        }
    }

    if (file != NULL) {
        if (bssid != NULL) {
            capture_packets(interface, bssid, file);
        } else {
            capture_packets(interface, NULL, file);
        }
    } else {
        // If no -w option is provided, list available networks
        list_networks();
    }

    return 0;
}
