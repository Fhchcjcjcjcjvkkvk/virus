#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NETWORKS 10
#define SSID_LENGTH 100
#define BSSID_LENGTH 20

// Structure to store Wi-Fi network information
typedef struct {
    char ssid[SSID_LENGTH];
    char bssid[BSSID_LENGTH];
    int signal_strength;
} WiFiNetwork;

int main() {
    // Declare an array to store Wi-Fi networks
    WiFiNetwork networks[MAX_NETWORKS];
    int network_count = 0;
    
    // Buffer to store the command output
    char line[256];

    // Open a process to execute the netsh command and get Wi-Fi networks
    FILE *fp = _popen("netsh wlan show networks", "r");
    if (fp == NULL) {
        perror("Failed to run netsh command");
        return 1;
    }

    // Read output line by line from the netsh command
    while (fgets(line, sizeof(line), fp)) {
        // Check for SSID line (example: "SSID 1 : MyNetwork")
        if (strncmp(line, "SSID", 4) == 0) {
            sscanf(line, "SSID %*d : \"%[^\"]\"", networks[network_count].ssid);
        }
        
        // Check for BSSID line (example: "BSSID 1 : 00:14:22:01:32:44")
        else if (strncmp(line, "BSSID", 5) == 0) {
            sscanf(line, "BSSID %*d : %s", networks[network_count].bssid);
        }
        
        // Check for Signal strength line (example: "Signal  : -65")
        else if (strncmp(line, "Signal", 6) == 0) {
            sscanf(line, "Signal  : %d", &networks[network_count].signal_strength);
            
            // After collecting full data for one network, increment the count
            network_count++;
        }
        
        // Stop if we've reached the maximum number of networks
        if (network_count >= MAX_NETWORKS) {
            break;
        }
    }

    // Close the process
    fclose(fp);

    // Print the results in a table format
    printf("Found Wi-Fi Networks:\n");
    printf("BSSID               SSID                           Signal Strength (dBm)\n");
    for (int i = 0; i < network_count; i++) {
        printf("%-20s %-30s %-20d\n", networks[i].bssid, networks[i].ssid, networks[i].signal_strength);
    }

    return 0;
}
