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
    const char *output_file = NULL;
    const char *bssid = NULL;
    
    if (argc == 1) {
        // No arguments: just show available networks
        list_networks();
        return 0;
    }
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            output_file = argv[i + 1];  // Get the file name for the output
            i++;  // Skip the next argument because it's the file name
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bssid = argv[i + 1];  // Get the BSSID
            i++;  // Skip the next argument because it's the BSSID
        } else {
            // Handle invalid argument usage
            printf("Invalid arguments. Usage:\n");
            printf("  airhunter       : List available networks\n");
            printf("  airhunter -w <filename> -b <BSSID> : Capture EAPOL packets for a specific BSSID\n");
            return 1;
        }
    }
    
    if (output_file && bssid) {
        // Both -w and -b were provided, capture packets
        capture_eapol(output_file, bssid);
    } else {
        // If -w or -b is missing
        printf("Invalid arguments. Usage:\n");
        printf("  airhunter       : List available networks\n");
        printf("  airhunter -w <filename> -b <BSSID> : Capture EAPOL packets for a specific BSSID\n");
    }
    
    return 0;
}
