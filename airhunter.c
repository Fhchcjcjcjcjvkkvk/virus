#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void capture_packets(const char* output_file, const char* bssid) {
    char command[512];
    
    // Capture EAPOL packets and save to the specified .pcap file
    // This will invoke tshark to capture EAPOL packets from the specified BSSID
    snprintf(command, sizeof(command), "tshark -i wlan0 -a duration:60 -f \"ether host %s and wlan[0] == 0x08\" -w %s", bssid, output_file);
    
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

    printf("Listing available networks (BSSID, ESSID, Encryption):\n");

    // Open the command for reading
    fp = _popen(command, "r");
    if (fp == NULL) {
        printf("Failed to run command.\n");
        return;
    }

    // Read the output line by line
    while (fgets(path, sizeof(path), fp) != NULL) {
        // Print only the lines that contain BSSID, SSID (ESSID), and Encryption information
        if (strstr(path, "BSSID") != NULL || strstr(path, "SSID") != NULL || strstr(path, "Encryption") != NULL) {
            printf("%s", path);
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
