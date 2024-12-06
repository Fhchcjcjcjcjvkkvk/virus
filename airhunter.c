#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Function prototypes
void showNetworks();
void capturePackets(const char *filename, const char *bssid);

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // If no arguments are provided, show available networks
        showNetworks();
    } else if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0) {
        // If arguments match the packet capture mode
        const char *filename = argv[2];
        const char *bssid = argv[4];
        capturePackets(filename, bssid);
    } else {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  airhunter                - Show available networks\n");
        fprintf(stderr, "  airhunter -w <file> -b <BSSID> - Capture EAPOL packets\n");
        return 1;
    }

    return 0;
}

void showNetworks() {
    printf("Scanning for networks...\n\n");

    // Use tshark to scan for networks
    const char *command = "tshark -I -i Wi-Fi -Y \"wlan.fc.type_subtype == 0x08\" -T fields -e wlan.sa -e wlan.ssid -e wlan.rsn.akms.type -e wlan.rssi";
    FILE *pipe = _popen(command, "r");

    if (!pipe) {
        fprintf(stderr, "Error: Failed to execute tshark. Make sure it is installed and in your PATH.\n");
        return;
    }

    printf("BSSID               ESSID               ENCRYPTION        RSSI\n");
    printf("----------------------------------------------------------------------\n");

    char line[512];
    while (fgets(line, sizeof(line), pipe)) {
        printf("%s", line);
    }

    _pclose(pipe);
}

void capturePackets(const char *filename, const char *bssid) {
    printf("Starting packet capture for BSSID %s...\n", bssid);

    // Build tshark command to capture EAPOL packets
    char command[1024];
    snprintf(command, sizeof(command), "tshark -I -i Wi-Fi -w %s -Y \"eapol && wlan.sa == %s\"", filename, bssid);

    int result = system(command);
    if (result != 0) {
        fprintf(stderr, "Error: Failed to execute tshark.\n");
        return;
    }

    printf("Capture complete. Checking for EAPOL handshakes...\n");

    // Analyze the .pcap file for EAPOL handshakes
    snprintf(command, sizeof(command), "tshark -r %s -Y \"eapol\"", filename);
    FILE *pipe = _popen(command, "r");

    if (!pipe) {
        fprintf(stderr, "Error: Failed to analyze capture file.\n");
        return;
    }

    char line[512];
    int eapolCount = 0;
    while (fgets(line, sizeof(line), pipe)) {
        eapolCount++;
    }

    _pclose(pipe);

    if (eapolCount > 0) {
        printf("EAPOL handshakes detected. Packets saved to %s.\n", filename);
    } else {
        printf("No EAPOL handshakes detected. Capture file will not be saved.\n");
        remove(filename);
    }
}
