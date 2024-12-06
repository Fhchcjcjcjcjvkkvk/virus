#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define EAPOL_TYPE 0x888e

// Structure for capturing packets
struct packet_info {
    struct pcap_pkthdr header;
    const u_char *packet;
};

// Callback function to handle captured packets
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct packet_info *info = (struct packet_info *)user_data;
    info->header = *pkthdr;
    info->packet = packet;

    // Check if packet is EAPOL (WPA handshake)
    if (packet[12] == 0x88 && packet[13] == 0x8e) {
        printf("WPA Handshake found!\n");
    }
}

// Function to find the Wi-Fi interface
pcap_t *find_wifi_interface(char *errbuf) {
    pcap_if_t *interfaces, *dev;
    pcap_t *handle = NULL;
    int found = 0;

    // Get the list of all available interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        printf("Error finding interfaces: %s\n", errbuf);
        return NULL;
    }

    // Iterate through the interfaces and select a Wi-Fi one (usually has 'wifi' in the name)
    for (dev = interfaces; dev != NULL; dev = dev->next) {
        if (strstr(dev->name, "wifi") != NULL) {
            // Open the selected interface for packet capture
            handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                printf("Error opening device %s: %s\n", dev->name, errbuf);
            } else {
                printf("Capturing on Wi-Fi interface: %s\n", dev->name);
                found = 1;
                break;
            }
        }
    }

    // Free the device list
    pcap_freealldevs(interfaces);

    if (!found) {
        printf("No Wi-Fi interface found\n");
    }

    return handle;
}

// Function to start capturing packets
void capture_packets(const char *filename, int capture_duration) {
    pcap_t *handle;
    pcap_dumper_t *pcap_file;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find and open the Wi-Fi interface
    handle = find_wifi_interface(errbuf);
    if (handle == NULL) {
        return;
    }

    // Open the pcap file to write the captured packets
    pcap_file = pcap_dump_open(handle, filename);
    if (pcap_file == NULL) {
        printf("Error opening pcap file: %s\n", filename);
        pcap_close(handle);
        return;
    }

    // Create packet info structure
    struct packet_info info;

    // Capture packets for the specified duration
    time_t start_time = time(NULL);
    while (difftime(time(NULL), start_time) < capture_duration) {
        if (pcap_loop(handle, 1, packet_handler, (unsigned char *)&info) < 0) {
            printf("Error capturing packet: %s\n", pcap_geterr(handle));
            break;
        }

        // Write the packet to the pcap file
        pcap_dump((unsigned char *)pcap_file, &info.header, info.packet);
    }

    // Close pcap handle and file
    pcap_dump_close(pcap_file);
    pcap_close(handle);

    printf("Capture complete. Data saved to %s\n", filename);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: airhunter.exe -w <output_file>\n");
        return 1;
    }

    // Parse command-line arguments
    const char *filename = argv[2];
    const int capture_duration = 60;  // Capture for 60 seconds

    printf("Starting packet capture for 60 seconds...\n");

    // Capture packets and save to the specified file
    capture_packets(filename, capture_duration);

    return 0;
}
