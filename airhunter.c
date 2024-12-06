#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Function to list networks with details (BSSID, ESSID, Encryption, RSSI)
void list_networks() {
    printf("Listing available networks with RSSI...\n");
    
    // Use tshark to scan and display BSSID, ESSID, Encryption, and RSSI
    system("tshark -i \"Wi-Fi\" -Y \"wlan.fc.type_subtype == 0x08\" -T fields -e wlan.bssid -e wlan.ssid -e wlan_radio.signal_dbm -e wlan.wlan_radio.channel");
}

// Function to capture packets for a specific BSSID and save to a .pcap file
void capture_packets(const char *file_name, const char *bssid) {
    printf("Capturing packets for BSSID: %s and saving to %s...\n", bssid, file_name);

    // Command to start tshark capture for EAPOL handshakes, using interface 'Wi-Fi' on Windows
    char command[512];
    snprintf(command, sizeof(command), "tshark -i \"Wi-Fi\" -a duration:60 -w %s -Y \"eapol && wlan.bssid==%s\"", file_name, bssid);

    int result = system(command);
    if (result != 0) {
        printf("Error capturing packets\n");
    }
}

// Function to parse command line arguments and decide which action to take
void parse_arguments(int argc, char *argv[]) {
    if (argc == 1) {
        // No parameters provided, just list networks
        list_networks();
    } else if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0) {
        // Capture packets if -w and -b are specified
        const char *file_name = argv[2];
        const char *bssid = argv[4];
        capture_packets(file_name, bssid);
    } else {
        printf("Usage: airhunter [-w <file_name>] [-b <BSSID>]\n");
    }
}

int main(int argc, char *argv[]) {
    parse_arguments(argc, argv);
    return 0;
}
