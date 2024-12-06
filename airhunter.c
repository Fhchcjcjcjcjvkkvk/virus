#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage(const char *prog_name) {
    printf("Usage: %s -a <AP_MAC>\n", prog_name);
    printf("Options:\n");
    printf("  -a <AP_MAC>   Show stations associated with a specific AP\n");
    printf("If no options are provided, lists nearby networks.\n");
}

void capture_networks() {
    printf("Scanning for nearby networks...\n");
    // Change wlan0 to the appropriate Wi-Fi adapter name for Windows
    system("tshark -i Wi-Fi -Y \"wlan.fc.type_subtype == 0x08\" -T fields -e wlan.ssid -e wlan.bssid -e radiotap.dbm_antsignal -e wlan.channel");
}

void capture_stations(const char *ap_mac) {
    printf("Scanning for stations associated with AP: %s\n", ap_mac);
    char command[512];
    // Create the tshark command for detecting stations
    snprintf(command, sizeof(command),
             "tshark -i Wi-Fi -Y \"wlan.bssid == %s && wlan.fc.type_subtype == 0x20\" -T fields -e wlan.sa -e wlan.da -e wlan.fc.type_subtype",
             ap_mac);
    system(command);
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        usage(argv[0]);
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "-a") == 0) {
        capture_stations(argv[2]);
    } else {
        usage(argv[0]);
    }

    return 0;
}
