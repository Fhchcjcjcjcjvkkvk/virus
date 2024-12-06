#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to list available Wi-Fi networks
void list_networks() {
    printf("Listing available networks...\n");
    // Use netsh to list networks with details such as BSSID, ESSID, encryption
    system("netsh wlan show networks mode=bssid");
}

// Function to capture EAPOL packets using tshark
void capture_eapol(const char *output_file, const char *bssid) {
    char command[512];
    
    // Modify the tshark command for Windows, assuming "Wi-Fi" is the interface name
    snprintf(command, sizeof(command), "tshark -i Wi-Fi -a duration:60 -w %s -Y eapol -f \"ether host %s\"", output_file, bssid);
    
    // Run the command to capture EAPOL packets
    printf("Capturing packets for BSSID %s...\n", bssid);
    int ret = system(command);
    
    if (ret != 0) {
        printf("Error capturing packets or no EAPOL packets detected.\n");
    } else {
        printf("Capture complete. File saved as %s.\n", output_file);
    }
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // No arguments: just show available networks
        list_networks();
    } else if (argc == 4 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-b") == 0) {
        // Arguments are in the form: airhunter -w capture.pcap -b 78:57:57:8:57
        const char *output_file = argv[2];
        const char *bssid = argv[4];
        
        // Capture packets with EAPOL
        capture_eapol(output_file, bssid);
    } else {
        printf("Invalid arguments. Usage:\n");
        printf("  airhunter       : List available networks\n");
        printf("  airhunter -w <filename> -b <BSSID> : Capture EAPOL packets for a specific BSSID\n");
    }
    
    return 0;
}
