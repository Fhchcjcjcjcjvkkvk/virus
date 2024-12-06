#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to display available networks
void showNetworks() {
    printf("Listing available networks...\n");
    // You might need to change the interface name to your actual Wi-Fi interface (e.g., Wi-Fi, Ethernet)
    system("tshark -i Wi-Fi -Y 'wlan.fc.type_subtype == 0x08' -T fields -e wlan.bssid -e wlan.ssid -e wlan.radio.encryption -e wlan.beacon");
}

// Function to capture packets and save to a .pcap file
void capturePackets(const char* bssid, const char* filename) {
    printf("Capturing packets for BSSID %s, saving to %s...\n", bssid, filename);
    // Constructing the tshark command for capturing EAPOL frames
    char command[256];
    snprintf(command, sizeof(command), "tshark -i Wi-Fi -f \"ether host %s\" -Y eapol -w %s", bssid, filename);
    
    // Running the tshark command to capture packets
    int result = system(command);
    
    // Check for errors during capture
    if (result == 0) {
        printf("Capture complete.\n");
    } else {
        printf("Error during capture.\n");
    }
}

// Main function to parse arguments and perform actions
int main(int argc, char *argv[]) {
    if (argc == 1) {
        // If no arguments, show available networks
        showNetworks();
    } else if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0) {
        // If arguments include -w for file output and -b for BSSID
        const char* filename = argv[2];
        const char* bssid = argv[4];
        
        // Capture packets for the specified BSSID and write to file
        capturePackets(bssid, filename);
    } else {
        // Print usage instructions
        printf("Usage:\n");
        printf("  airhunter            # Show available networks\n");
        printf("  airhunter -w <file> -b <BSSID>  # Capture packets from BSSID and save to file\n");
    }
    
    return 0;
}
