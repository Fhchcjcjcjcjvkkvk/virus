#include <stdio.h>
#include <stdlib.h>

int main() {
    // Command to capture Wi-Fi networks with SSID and BSSID using tshark
    // Replace 'Wi-Fi' with your network interface name (it could be something like 'Wi-Fi', 'Ethernet', etc.)
    // This command captures the BSSID and SSID for networks in range.
    const char *tshark_command = "tshark -i Wi-Fi -Y 'wlan.fc.type_subtype == 0x08' -T fields -e wlan.ssid -e wlan.bssid";

    // Run the tshark command and display the output
    FILE *fp = popen(tshark_command, "r");
    if (fp == NULL) {
        perror("Failed to run tshark command");
        return 1;
    }

    // Print the networks found with SSID and BSSID
    printf("Available Networks:\n");
    char result[1024];
    while (fgets(result, sizeof(result), fp) != NULL) {
        printf("%s", result);
    }

    // Close the file pointer
    fclose(fp);
    return 0;
}
