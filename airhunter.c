#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_COMMAND_LEN 512

void list_networks() {
    printf("Scanning for available networks...\n");
    // Use tshark to list networks with BSSID, ESSID, encryption, and RSSI.
    system("tshark -i WIFI -Y \"wlan.fc.type_subtype == 0x08\" -T fields -e wlan.bssid -e wlan.ssid -e wlan.rsn -e radiotap.dbm_antsignal");
}

void capture_eapol(const char *filename, const char *bssid) {
    char command[MAX_COMMAND_LEN];

    printf("Starting packet capture for BSSID: %s\n", bssid);

    // Build the tshark command to capture EAPOL packets.
    snprintf(command, sizeof(command), "tshark -i WIFI -Y \"wlan.addr == %s && eapol\" -w %s", bssid, filename);

    int result = system(command);
    if (result != 0) {
        printf("Error capturing packets. Make sure tshark is installed and you have proper permissions.\n");
    } else {
        printf("Capture completed. Packets saved to %s\n", filename);
    }
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // If no arguments, display available networks.
        list_networks();
    } else if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0) {
        const char *filename = argv[2];
        const char *bssid = argv[4];

        capture_eapol(filename, bssid);
    } else {
        printf("Usage:\n");
        printf("  airhunter               - List available networks\n");
        printf("  airhunter -w <file> -b <BSSID> - Capture EAPOL packets for the specified BSSID and save to <file>\n");
    }

    return 0;
}
