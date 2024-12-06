#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void capture_packets(const char* output_file, const char* bssid) {
    char command[512];
    
    // Capture EAPOL packets and save to the specified .pcap file
    snprintf(command, sizeof(command), "tshark -i Wi-Fi -a duration:60 -f \"ether host %s and wlan[0] == 0x08\" -w %s", bssid, output_file);
    
    printf("Capturing packets... Please wait.\n");
    int result = system(command);  // Executes the tshark command
    
    if (result == 0) {
        printf("Capture completed and saved to %s\n", output_file);
    } else {
        printf("Error during capture.\n");
    }
}

void list_networks() {
    char command[] = "netsh wlan show networks mode=Bssid";
    FILE *fp;
    char path[1035];

    printf("Listing available networks (BSSID, ESSID, Encryption, Signal Strength):\n");

    // Open the command for reading
    fp = _popen(command, "r");
    if (fp == NULL) {
        printf("Failed to run command.\n");
        return;
    }

    // Print the entire output for debugging
    printf("Raw output from netsh wlan show networks mode=Bssid:\n");

    int output_found = 0;

    while (fgets(path, sizeof(path), fp) != NULL) {
        printf("%s", path);  // Debugging: print the raw output line by line
        
        // Check if there is any network output by searching for a specific field
        if (strstr(path, "BSSID") != NULL) {
            output_found = 1;
        }
    }

    if (!output_found) {
        printf("No networks found or the command output is empty.\n");
        _pclose(fp);
        return;
    }

    // Rewind the file pointer to parse the relevant details
    rewind(fp);
    
    char bssid[18], essid[256], encryption[256], signal[256];
    int line_number = 0;

    // Extract and display network information
    while (fgets(path, sizeof(path), fp) != NULL) {
        // Clean up any leading/trailing whitespace
        path[strcspn(path, "\r\n")] = 0;

        // Capture BSSID, ESSID, Encryption, and Signal values
        if (strstr(path, "BSSID") != NULL) {
            sscanf(path, "    BSSID %*d : %s", bssid);
            line_number = 1; // We found BSSID
        } 
        else if (strstr(path, "SSID") != NULL && line_number == 1) {
            sscanf(path, "        SSID %*d  : %[^\n]", essid);
            line_number = 2; // We found ESSID
        }
        else if (strstr(path, "Encryption") != NULL && line_number == 2) {
            sscanf(path, "        Encryption   : %[^\n]", encryption);
            line_number = 3; // We found Encryption
        }
        else if (strstr(path, "Signal") != NULL && line_number == 3) {
            sscanf(path, "        Signal       : %s", signal);
            line_number = 0; // Reset after reading a full network info block

            // Format Signal Strength (RSSI) to display as requested: e.g., "54-"
            int signal_strength = atoi(signal); // Convert Signal to integer
            if (signal_strength >= 0) {
                printf("BSSID: %-18s ESSID: %-30s Encryption: %-20s Signal Strength: %-3d-\n", bssid, essid, encryption, signal_strength);
            } else {
                printf("BSSID: %-18s ESSID: %-30s Encryption: %-20s Signal Strength: Unknown\n", bssid, essid, encryption);
            }
        }
    }

    // Close the file pointer
    _pclose(fp);
}

int main(int argc, char *argv[]) {
    // If no arguments are passed, list available networks.
    if (argc == 1) {
        list_networks();
        return 0;
    }

    if (argc != 5) {
        printf("Usage: %s -w <output_file> -b <BSSID>\n", argv[0]);
        return 1;
    }
    
    // Parse input arguments for output file and BSSID
    char* output_file = NULL;
    char* bssid = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0) {
            output_file = argv[i+1];
            i++;
        } else if (strcmp(argv[i], "-b") == 0) {
            bssid = argv[i+1];
            i++;
        }
    }

    if (output_file == NULL || bssid == NULL) {
        printf("Error: Missing required parameters.\n");
        return 1;
    }
    
    // Capture packets for the specified BSSID and write to the output file
    capture_packets(output_file, bssid);

    return 0;
}
