#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NETWORKS 100
#define ESSID_MAX_LENGTH 32
#define BSSID_LENGTH 17
#define MAX_STATIONS 100

// Structure to hold network information
struct network_info {
    char essid[ESSID_MAX_LENGTH];
    char bssid[BSSID_LENGTH + 1];
    int rssi;  // RSSI is in dBm
};

// Structure to hold station information
struct station_info {
    char mac_address[BSSID_LENGTH + 1];
    char interface_name[32];
};

// Global arrays to hold the networks and stations found
struct network_info networks[MAX_NETWORKS];
struct station_info stations[MAX_STATIONS];
int network_count = 0;
int station_count = 0;

// Function to parse the output of the netsh command for available networks
void parse_netsh_output(FILE *fp) {
    char line[256];
    struct network_info current_network;
    int in_network = 0;

    while (fgets(line, sizeof(line), fp)) {
        // Look for the start of a network block
        if (strstr(line, "SSID") != NULL && strstr(line, "BSSID") != NULL) {
            // Reset current network info for a new network
            in_network = 1;
            memset(&current_network, 0, sizeof(current_network));
        }

        // Get BSSID (MAC address of the access point)
        if (in_network && strstr(line, "BSSID") != NULL) {
            sscanf(line, "    BSSID %*d : %s", current_network.bssid);
        }

        // Get ESSID (network name)
        if (in_network && strstr(line, "SSID") != NULL) {
            sscanf(line, "    SSID %*d  : \"%[^\"]\"", current_network.essid);
        }

        // Get Signal Strength (RSSI)
        if (in_network && strstr(line, "Signal") != NULL) {
            sscanf(line, "    Signal  : %d", &current_network.rssi);
        }

        // End of a network block, save the network info
        if (in_network && line[0] == '\n') {
            if (current_network.essid[0] != '\0' && current_network.bssid[0] != '\0') {
                networks[network_count++] = current_network;
            }
            in_network = 0;
        }
    }
}

// Function to run the netsh command and parse the output for Wi-Fi networks
void scan_wifi() {
    FILE *fp;
    const char *command = "netsh wlan show networks mode=bssid";

    // Run the command and open the output as a file
    fp = _popen(command, "r");
    if (fp == NULL) {
        perror("Error opening netsh output");
        exit(1);
    }

    // Parse the output
    parse_netsh_output(fp);

    // Close the file pointer
    fclose(fp);
}

// Function to run the netsh command and parse the output for connected interfaces (stations)
void show_connected_stations() {
    FILE *fp;
    const char *command = "netsh wlan show interfaces";

    // Run the command and open the output as a file
    fp = _popen(command, "r");
    if (fp == NULL) {
        perror("Error opening netsh output");
        exit(1);
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        // Look for connected stations (MAC address of the interface)
        if (strstr(line, "Connected") != NULL) {
            sscanf(line, "    SSID                   : %*s");
        }
        if (strstr(line, "BSSID") != NULL) {
            sscanf(line, "    BSSID                  : %s", stations[station_count].mac_address);
            station_count++;
        }

    }

    fclose(fp);
}

// Function to display the networks found
void display_networks() {
    printf("\nFound Wi-Fi Networks:\n");
    printf("%-20s %-30s %-10s\n", "BSSID", "SSID", "Signal Strength (dBm)");
    for (int i = 0; i < network_count; i++) {
        printf("%-20s %-30s %-10d\n", networks[i].bssid, networks[i].essid, networks[i].rssi);
    }
}

// Function to display connected stations (clients)
void display_stations() {
    printf("\nConnected Stations (Clients):\n");
    printf("%-20s %-30s\n", "MAC Address", "Interface");
    for (int i = 0; i < station_count; i++) {
        printf("%-20s %-30s\n", stations[i].mac_address, stations[i].interface_name);
    }
}

int main() {
    // Scan for Wi-Fi networks
    scan_wifi();

    // Show connected stations (clients)
    show_connected_stations();

    // Display the found networks
    display_networks();

    // Display the stations
    display_stations();

    return 0;
}
