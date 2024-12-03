#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void scan_wifi_networks() {
    char buffer[1024];
    FILE *fp;

    // Run the netsh command to scan for WiFi networks and get the output
    fp = popen("netsh wlan show networks mode=bssid", "r");
    if (fp == NULL) {
        perror("popen");
        exit(1);
    }

    // Initialize variables to hold the details
    char bssid[100], essid[100], signal[100], beacon[100];
    int found_bssid = 0, found_essid = 0, found_signal = 0, found_beacon = 0;

    // Parse the output line by line
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strstr(buffer, "SSID") != NULL) {
            // Print ESSID
            sscanf(buffer, "    SSID %*d  : %[^\n]", essid);
            printf("ESSID: %s\n", essid);
            found_essid = 1;
        }
        else if (strstr(buffer, "BSSID") != NULL) {
            // Print BSSID
            sscanf(buffer, "    BSSID %*d  : %[^\n]", bssid);
            printf("BSSID: %s\n", bssid);
            found_bssid = 1;
        }
        else if (strstr(buffer, "Signal") != NULL) {
            // Print Signal Strength (PWR)
            sscanf(buffer, "        Signal  : %s", signal);
            printf("Signal (PWR): %s dBm\n", signal);
            found_signal = 1;
        }
        else if (strstr(buffer, "Beacon") != NULL) {
            // Print Beacon
            sscanf(buffer, "        Beacon : %s", beacon);
            printf("Beacon: %s\n", beacon);
            found_beacon = 1;
        }

        // Print values with colons when all details are found
        if (found_bssid && found_essid && found_signal && found_beacon) {
            printf("\n");
            found_bssid = found_essid = found_signal = found_beacon = 0;
        }
    }

    fclose(fp);
}

int main() {
    printf("Scanning for WiFi networks...\n");
    scan_wifi_networks();
    return 0;
}
