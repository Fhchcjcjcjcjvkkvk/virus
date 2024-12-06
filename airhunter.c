#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void print_usage() {
    printf("Usage: airhunter [-w <filename>] [-b <BSSID>]\n");
    printf("  -w <filename> : Write captured packets to <filename> (in .pcap format)\n");
    printf("  -b <BSSID>    : Specify the BSSID of the network to capture packets from\n");
}

void show_networks() {
    // Use `tshark` or similar command to list available networks with BSSID, ESSID, and Encryption
    printf("Scanning available networks...\n");

    // List networks with BSSID, ESSID, and Encryption using tshark
    system("tshark -i wlan0 --bpf 'type mgt' -Y 'wlan.fc.type_subtype == 0x08' -T fields -e wlan.bssid -e wlan.ssid -e wlan.wep -e wlan.capabilities");
}

void capture_eapol(const char *filename, const char *bssid) {
    char command[256];
    printf("Capturing EAPOL packets from BSSID: %s\n", bssid);

    // Construct the tshark command to capture EAPOL packets
    snprintf(command, sizeof(command), "tshark -i wlan0 -Y 'eapol' -w %s -f 'ether host %s'", filename, bssid);
    
    // Run the tshark command and capture EAPOL packets
    int status = system(command);
    if (status != 0) {
        printf("Error capturing packets. Please check if the Wi-Fi interface is in monitor mode.\n");
    } else {
        printf("Capture completed. The packets are saved to %s\n", filename);
    }
}

int main(int argc, char *argv[]) {
    char *filename = NULL;
    char *bssid = NULL;

    if (argc == 1) {
        // No arguments, just show networks
        show_networks();
        return 0;
    }

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0) {
            if (i + 1 < argc) {
                filename = argv[++i];
            } else {
                printf("Error: Missing filename after -w\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-b") == 0) {
            if (i + 1 < argc) {
                bssid = argv[++i];
            } else {
                printf("Error: Missing BSSID after -b\n");
                return 1;
            }
        }
    }

    if (filename && bssid) {
        // Both -w and -b are provided, capture EAPOL packets
        capture_eapol(filename, bssid);
    } else {
        // If only -w is provided, show networks
        if (!filename) {
            printf("Error: -w (output filename) is required for capturing packets.\n");
            return 1;
        }
        if (!bssid) {
            printf("Error: -b (BSSID) is required for capturing packets.\n");
            return 1;
        }
    }

    return 0;
}
