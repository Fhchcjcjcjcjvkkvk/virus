#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024

void executeTsharkCommand(const char *command, const char *outputFile) {
    char cmd[BUFFER_SIZE];
    snprintf(cmd, BUFFER_SIZE, "%s > %s", command, outputFile);
    system(cmd);
}

void parseNetworks(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    printf("\nNearby Networks:\n");
    printf("BSSID\t\t\tSSID\t\tSignal Strength\n");
    printf("-------------------------------------------------------\n");

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "BSSID") || strstr(line, "SSID")) continue; // Skip header
        // Parsing example: Adjust to match tshark output format
        char bssid[32], ssid[128], signal[16];
        if (sscanf(line, "%31s %127s %15s", bssid, ssid, signal) == 3) {
            printf("%-20s %-20s %-10s\n", bssid, ssid, signal);
        }
    }
    fclose(file);
}

void parseStations(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    printf("\nAssociated Stations:\n");
    printf("MAC Address\t\tAP MAC Address\t\tSignal Strength\n");
    printf("-----------------------------------------------------------\n");

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "Station") || strstr(line, "MAC")) continue; // Skip header
        // Parsing example: Adjust to match tshark output format
        char stationMac[32], apMac[32], signal[16];
        if (sscanf(line, "%31s %31s %15s", stationMac, apMac, signal) == 3) {
            printf("%-20s %-20s %-10s\n", stationMac, apMac, signal);
        }
    }
    fclose(file);
}

int main() {
    const char *networksFile = "networks.txt";
    const char *stationsFile = "stations.txt";

    // Execute tshark commands to capture network and station data
    executeTsharkCommand("tshark -i Wi-Fi -Y \"wlan.fc.type_subtype == 0x08\" -T fields -e wlan.bssid -e wlan.ssid -e radiotap.dbm_antsignal", networksFile);
    executeTsharkCommand("tshark -i Wi-Fi -Y \"wlan.fc.type_subtype == 0x0A\" -T fields -e wlan.ta -e wlan.ra -e radiotap.dbm_antsignal", stationsFile);

    // Parse and display the output
    parseNetworks(networksFile);
    parseStations(stationsFile);

    return 0;
}
