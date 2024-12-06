#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define CAPTURE_DURATION 60  // Capture duration in seconds

// Function to handle Ctrl+C interrupt to stop capture
void sigint_handler(int sig) {
    printf("\nCapture interrupted!\n");
    exit(0);
}

// Function to scan available Wi-Fi networks and parse their BSSID, ESSID, and Encryption type
void scan_networks(char *interface_name) {
    FILE *fp;
    char buffer[1024];
    int network_count = 0;

    // Run the netsh command to list Wi-Fi networks with BSSID and Encryption info
    char command[256];
    sprintf(command, "netsh wlan show networks mode=bssid interface=%s", interface_name);

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Error running netsh command");
        return;
    }

    // Parse the output of the command
    printf("Scanning for Wi-Fi networks on interface %s...\n", interface_name);
    printf("------------------------------------------------------------\n");
    printf("Index | BSSID             | ESSID             | Encryption\n");
    printf("------------------------------------------------------------\n");

    // Iterate through each line in the command output
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "SSID") && strstr(buffer, "BSSID")) {
            char essid[100], bssid[20], encryption[50];
            int essid_found = 0, bssid_found = 0, encryption_found = 0;

            // Check for ESSID
            if (strstr(buffer, "SSID") && !essid_found) {
                sscanf(buffer, "    SSID %*d  : %99[^\n]", essid);
                essid_found = 1;
            }

            // Check for BSSID
            if (strstr(buffer, "BSSID") && !bssid_found) {
                sscanf(buffer, "    BSSID %*d  : %19s", bssid);
                bssid_found = 1;
            }

            // Check for Encryption
            if (strstr(buffer, "Encryption") && !encryption_found) {
                sscanf(buffer, "    Encryption   : %49[^\n]", encryption);
                encryption_found = 1;
            }

            // If all fields are found, print the network info
            if (essid_found && bssid_found && encryption_found) {
                network_count++;
                printf("%-6d| %-18s| %-18s| %-12s\n", network_count, bssid, essid, encryption);
                essid_found = 0;
                bssid_found = 0;
                encryption_found = 0;
            }
        }
    }

    if (network_count == 0) {
        printf("No networks found.\n");
    }

    fclose(fp);
}

// Function to capture WPA handshake packets using Wireshark/Npcap via command line
void capture_packets(char *interface_name, char *bssid, char *filename) {
    // Use Npcap (Wireshark) to capture packets for WPA handshake (EAPOL)
    char command[256];
    
    printf("Capturing packets for WPA handshake on BSSID %s...\n", bssid);

    // Run Wireshark/Npcap capture command in the background
    sprintf(command, "tshark -i %s -a duration:%d -f \"wlan type mgt subtype beacon or wlan type data and wlan addr2 %s\" -w %s", 
            interface_name, CAPTURE_DURATION, bssid, filename);

    // Execute the capture command
    int result = system(command);
    if (result != 0) {
        printf("Error running the capture command. Make sure Wireshark or Npcap is installed and properly configured.\n");
        return;
    }

    printf("Capture finished. WPA Handshake (if any) saved to %s\n", filename);
}

int main() {
    char interface_name[50];
    char filename[100];
    char bssid[20];

    // Display available interfaces
    FILE *fp = popen("netsh wlan show interfaces", "r");
    if (!fp) {
        printf("Error retrieving interface list.\n");
        return 1;
    }

    printf("Available interfaces:\n");
    // List interfaces from netsh or from any other method
    // Use Wireshark's or Npcap's interface names (e.g., wlan0, eth0)
    // or assume a default Wi-Fi interface name
    strcpy(interface_name, "Wi-Fi");

    // Scan Wi-Fi networks on the selected interface
    scan_networks(interface_name);

    // Ask user to select a network (BSSID)
    printf("Enter the BSSID of the network to capture EAPOL (e.g., 00:14:22:01:23:45): ");
    scanf("%s", bssid);

    // Ask user for the filename to save the capture
    printf("Enter the filename to save the capture (e.g., capture.pcap): ");
    scanf("%s", filename);

    // Start packet capture
    capture_packets(interface_name, bssid, filename);

    return 0;
}
