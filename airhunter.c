#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

void display_networks_with_stations() {
    // Run a command to display available networks with BSSID, ESSID, encryption, and stations
    printf("Showing available networks with stations...\n");
    system("netsh wlan show networks mode=bssid");

    // Use tshark to list connected clients (stations)
    // Here we assume the Wi-Fi interface name is 'Wi-Fi', you can change if necessary
    printf("\nStations connected to your Wi-Fi interface:\n");
    system("tshark -i Wi-Fi -Y 'wlan.fc.type_subtype == 0x08' -T fields -e wlan.addr");
}

void capture_packets(const char* bssid, const char* output_file) {
    // Command to capture EAPOL packets using tshark
    char command[256];
    snprintf(command, sizeof(command), "tshark -i Wi-Fi -w %s -b %s", output_file, bssid);
    
    printf("Capturing packets for BSSID %s. Press Ctrl+C to stop.\n", bssid);
    
    // Run the tshark command to capture packets
    int result = system(command);
    
    if (result != 0) {
        printf("Error: Failed to capture packets.\n");
    } else {
        printf("Capture completed. Output saved to %s.\n", output_file);
    }
}

int main(int argc, char* argv[]) {
    // If no arguments are provided, show available networks with stations
    if (argc == 1) {
        display_networks_with_stations();
    } 
    // If -w and -b arguments are provided, capture packets
    else if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0) {
        const char* output_file = argv[2];
        const char* bssid = argv[4];

        printf("Starting packet capture...\n");
        capture_packets(bssid, output_file);
    } else {
        printf("Usage: \n");
        printf("airhunter          - Show available networks with stations\n");
        printf("airhunter -w <file> -b <bssid> - Capture packets for a specific BSSID\n");
    }

    return 0;
}
