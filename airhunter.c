#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_BUFFER_SIZE 1024

// Function to execute a command in the system shell
void executeCommand(const char *command) {
    system(command);
}

// Function to display available networks
void showNetworks() {
    printf("Scanning for available networks...\n");
    // This is done using 'netsh wlan show networks mode=bssid' in Windows
    executeCommand("netsh wlan show networks mode=bssid");
}

// Function to capture EAPOL packets with tshark
void capturePackets(const char *fileName, const char *bssid) {
    char command[MAX_BUFFER_SIZE];
    // Assuming the interface is named "Wi-Fi" for most systems, but you can change this if needed.
    const char *wifi_interface = "Wi-Fi";  // Changed variable name from 'interface' to 'wifi_interface'
    
    snprintf(command, sizeof(command), "tshark -i \"%s\" -f \"ether proto 0x888e and wlan addr1 %s\" -w %s", wifi_interface, bssid, fileName);
    
    printf("Capturing EAPOL packets from BSSID: %s\n", bssid);
    executeCommand(command);

    // After capture, check if handshake was captured
    // Let's run tshark again to verify if any EAPOL packets were captured
    printf("Checking for EAPOL packets...\n");
    snprintf(command, sizeof(command), "tshark -r %s -Y eapol", fileName);
    FILE *fp = _popen(command, "r");

    if (fp == NULL) {
        printf("Error checking pcap file\n");
        return;
    }

    char output[MAX_BUFFER_SIZE];
    int eapolFound = 0;

    while (fgets(output, sizeof(output), fp) != NULL) {
        if (strstr(output, "EAPOL") != NULL) {
            eapolFound = 1;
            break;
        }
    }

    fclose(fp);

    if (eapolFound) {
        printf("EAPOL handshake found! Capture successful.\n");
    } else {
        printf("No EAPOL packets found! Stopping capture.\n");
        // Optionally, remove the file if no EAPOL found
        snprintf(command, sizeof(command), "del %s", fileName);
        executeCommand(command);
    }
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // No arguments provided, list networks
        showNetworks();
    } else if (argc == 4 && strcmp(argv[1], "-w") == 0 && strcmp(argv[2], "-b") == 0) {
        // Arguments: airhunter -w <file_name> -b <BSSID>
        char *fileName = argv[2];
        char *bssid = argv[3];
        
        // Capture packets with the provided BSSID and save to file
        capturePackets(fileName, bssid);
    } else {
        printf("Usage:\n");
        printf("  airhunter         - Scan and display available networks\n");
        printf("  airhunter -w <file_name> -b <BSSID> - Capture EAPOL packets for the specified BSSID and save to file\n");
    }

    return 0;
}
