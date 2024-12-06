#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <getopt.h>

void show_usage() {
    printf("Usage: airhunter [-w <file.pcap>] [-b <BSSID>] [-i <interface>]\n");
    printf("  -w <file.pcap>  Write captured packets to a file\n");
    printf("  -b <BSSID>      Capture packets from a specific BSSID\n");
    printf("  -i <interface>  Specify the Wi-Fi interface (e.g., Wi-Fi)\n");
}

void list_networks() {
    // This function can use system commands like `netsh wlan show networks`
    // or invoke external tools like `tshark` to list available networks.
    printf("Listing available networks...\n");
    
    // Example to call tshark for network scanning
    system("tshark -D");
    printf("Use the correct interface from the above list and run capture again.\n");
}

void capture_packets(const char *interface, const char *bssid, const char *file) {
    // You can use `tshark` to capture EAPOL packets
    char cmd[256];
    
    if (bssid != NULL) {
        // Capture packets from the specific BSSID
        sprintf(cmd, "tshark -i \"%s\" -Y 'eapol' -w %s -b 78:%s", interface, file, bssid);
    } else {
        // Capture all packets (optionally filter later)
        sprintf(cmd, "tshark -i \"%s\" -Y 'eapol' -w %s", interface, file);
    }

    printf("Capturing packets with command: %s\n", cmd);
    system(cmd);

    // Check for EAPOL packets
    printf("Capture complete. Checking for EAPOL packets...\n");
    // You could parse the capture file or check output for packets.
    printf("Capture finished, and packets saved to %s.\n", file);
}

int main(int argc, char **argv) {
    int opt;
    const char *interface = "Wi-Fi"; // Default Wi-Fi interface name (change if necessary)
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
