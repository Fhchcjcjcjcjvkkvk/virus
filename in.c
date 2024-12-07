#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>

// Define the 802.11 frame header length
#define WIFI_HEADER_LEN 24

// Structure to store information about Access Points
typedef struct {
    char ssid[33];
    char bssid[18];
    int signal_strength;
    char encryption[16];
} access_point_t;

// Function to print AP information
void print_ap_info(access_point_t *ap) {
    printf("SSID: %-32s | BSSID: %-17s | Signal Strength: %ddBm | Encryption: %s\n", 
           ap->ssid, ap->bssid, ap->signal_strength, ap->encryption);
}

// Callback function to handle each captured packet
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    access_point_t ap;

    // Example of extracting BSSID and signal strength (simplified)
    snprintf(ap.bssid, sizeof(ap.bssid), "%02x:%02x:%02x:%02x:%02x:%02x", 
             packet[10], packet[11], packet[12], packet[13], packet[14], packet[15]);
    ap.signal_strength = packet[0]; // Assume RSSI is in the first byte for simplicity

    // Example SSID and encryption (for demonstration, real implementation will need proper parsing)
    snprintf(ap.ssid, sizeof(ap.ssid), "Example SSID");
    strcpy(ap.encryption, "WPA2");

    // Print captured AP information
    print_ap_info(&ap);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the network device for packet capture (in monitor mode)
    // Replace "wlan0" with your actual Wi-Fi interface name, e.g., "Wi-Fi" on Windows
    handle = pcap_open_live("Wi-Fi", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    // Start capturing packets and call packet_handler for each packet
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error during capture: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_close(handle);
    return 0;
}
