#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Function to run a system command and print output
void run_command(const char *command) {
    FILE *fp;
    char result[1024];

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Error running command");
        return;
    }

    while (fgets(result, sizeof(result), fp) != NULL) {
        printf("%s", result);
    }

    fclose(fp);
}

// Function to list available networks
void list_networks() {
    printf("Listing available networks...\n");

    // Run tshark to show available Wi-Fi networks on Windows
    const char *command = "tshark -i Wi-Fi -Y \"wlan.fc.type_subtype == 0x08\" -T fields -e wlan.sa -e wlan.ssid -e wlan_radio.signal_dbm";
    run_command(command);
}

// Function to capture EAPOL packets from a specific BSSID and save to a file
void capture_eapol_packets(const char *bssid, const char *file_name) {
    printf("Capturing EAPOL packets for BSSID: %s, saving to %s...\n", bssid, file_name);

    // Command to capture EAPOL packets for a given BSSID and write to a pcap file
    char command[256];
    snprintf(command, sizeof(command), "tshark -i Wi-Fi -a duration:60 -w %s -Y eapol -f \"ether host %s\"", file_name, bssid);
    run_command(command);
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // No arguments passed, just list networks
        list_networks();
    } else if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0) {
        // Arguments for capturing packets (e.g., airhunter -w capture.pcap -b 78:57:57:8:57)
        const char *file_name = argv[2];
        const char *bssid = argv[4];
        capture_eapol_packets(bssid, file_name);
    } else {
        printf("Usage:\n");
        printf("  airhunter -w <file.pcap> -b <BSSID>    Capture EAPOL packets for a BSSID\n");
        printf("  airhunter                             List available networks\n");
    }

    return 0;
}
