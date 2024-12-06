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

// Function to scan available Wi-Fi networks using PowerShell on Windows
void scan_networks(char *interface_name) {
    FILE *fp;
    char buffer[1024];
    int network_count = 0;

    // Command to run PowerShell script to list Wi-Fi networks
    char command[256];
    sprintf(command, "powershell -Command \"Get-NetWiFi -InterfaceAlias '%s' | Select-Object SSID, Authentication\"", interface_name);

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Error running PowerShell command");
        return;
    }

    // Parse the output of the command
    printf("Scanning for Wi-Fi networks on interface %s...\n", interface_name);
    printf("------------------------------------------------------------\n");
    printf("Index | ESSID             | Authentication\n");
    printf("------------------------------------------------------------\n");

    // Iterate through each line in the command output
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "SSID") && strstr(buffer, "Authentication")) {
            char essid[100], encryption[50];
            int essid_found = 0, encryption_found = 0;

            // Extract ESSID and Authentication (Encryption) info
            if (strstr(buffer, "SSID")) {
                sscanf(buffer, "    SSID : %99[^\n]", essid);
                essid_found = 1;
            }
            if (strstr(buffer, "Authentication")) {
                sscanf(buffer, "    Authentication : %49[^\n]", encryption);
                encryption_found = 1;
            }

            // If both ESSID and Encryption are found, print network info
            if (essid_found && encryption_found) {
                network_count++;
                printf("%-6d| %-18s| %-12s\n", network_count, essid, encryption);
                essid_found = 0;
                encryption_found = 0;
            }
        }
    }

    if (network_count == 0) {
        printf("No networks found.\n");
    }

    fclose(fp);
}

// Function to capture WPA handshake packets (EAPOL frames) using Wireshark/Npcap
void capture_packets(char *interface_name, char *bssid, char *filename) {
    // Use Npcap (Wireshark) to capture packets for WPA handshake (EAPOL)
    char command[256];
    
    printf("Capturing EAPOL frames for WPA handshake on BSSID %s...\n", bssid);

    // Run Wireshark/Npcap capture command in the background to capture EAPOL frames
    // The filter captures EAPOL frames (which are part of WPA handshakes) for the given BSSID
    sprintf(command, "tshark -i %s -a duration:%d -f \"wlan type data and wlan addr2 %s and eapol\" -w %s", 
            interface_name, CAPTURE_DURATION, bssid, filename);

    // Execute the capture command
    int result = system(command);
    if (result != 0) {
        printf("Error running the capture command. Make sure Wireshark or Npcap is installed and properly configured.\n");
        return;
    }

    printf("Capture finished. EAPOL handshake (if any) saved to %s\n", filename);
}

int main() {
    char interface_name[50];
    char filename[100];
    char bssid[20];

    // Display available interfaces using PowerShell command
    FILE *fp = popen("powershell -Command \"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name\"", "r");
    if (!fp) {
        printf("Error retrieving interface list.\n");
        return 1;
    }

    printf("Available interfaces:\n");
    // Read and list interfaces
    while (fgets(interface_name, sizeof(interface_name), fp)) {
        printf("- %s", interface_name);
    }
    fclose(fp);

    // Ask user to select an interface
    printf("\nEnter the name of the interface to scan (e.g., Wi-Fi): ");
    fgets(interface_name, sizeof(interface_name), stdin);
    interface_name[strcspn(interface_name, "\n")] = '\0'; // Remove the newline character

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
