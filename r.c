#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
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

// Function to capture packets for WPA handshake (EAPOL packets)
void capture_packets(char *interface_name, char *bssid, char *filename) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    time_t start_time = time(NULL);

    // Open the capture interface
    handle = pcap_open_live(interface_name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening capture interface: %s\n", errbuf);
        return;
    }

    // Open the output pcap file
    pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
    if (dumper == NULL) {
        fprintf(stderr, "Error opening output file: %s\n", filename);
        return;
    }

    // Capture for the specified duration or until Ctrl+C is pressed
    signal(SIGINT, sigint_handler);

    printf("Capturing packets for WPA handshake on BSSID %s...\n", bssid);
    int handshake_found = 0;
    while (time(NULL) - start_time < CAPTURE_DURATION) {
        packet = pcap_next(handle, &header);
        if (packet == NULL) {
            continue; // Skip empty packets
        }

        // If we have a packet, save it to the pcap file
        pcap_dump((u_char *)dumper, &header, packet);

        // Check for WPA handshake (EAPOL packets)
        if (header.len > 0 && packet[0] == 0x88 && packet[1] == 0x8e) {
            printf("WPA Handshake packet captured.\n");
            handshake_found = 1;
        }
    }

    // Close the capture
    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);
    pcap_close(handle);

    if (handshake_found) {
        printf("WPA Handshake found and saved to %s\n", filename);
    } else {
        printf("No WPA Handshake found during capture.\n");
    }
}

int main() {
    char interface_name[50];
    char filename[100];
    char bssid[20];

    // Display available interfaces
    pcap_if_t *alldevs, *dev;
    pcap_findalldevs(&alldevs, NULL);
    printf("Available interfaces:\n");
    int idx = 1;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%d. %s\n", idx++, dev->name);
    }

    // Ask user to select an interface
    printf("Enter the interface number to capture on: ");
    int interface_index;
    scanf("%d", &interface_index);
    dev = alldevs;
    for (int i = 1; i < interface_index; i++) {
        dev = dev->next;
    }
    strcpy(interface_name, dev->name);

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
