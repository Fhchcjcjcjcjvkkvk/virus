#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define EAPOL_TYPE 0x88

// Callback function to process captured packets
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Check if the packet contains an EAPOL frame (EtherType 0x88)
    if (packet[12] == 0x88 && packet[13] == 0x8e) {
        printf("EAPOL Packet Captured! Length: %d\n", pkthdr->len);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s -c <channel> -w <filename.pcap> -b <bssid>\n", argv[0]);
        return -1;
    }

    int channel = atoi(argv[2]);
    const char *filename = argv[4];
    const char *bssid = argv[6];

    // Open the pcap file for writing
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find the network device to capture from
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }

    pcap_if_t *dev;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("Device: %s\n", dev->name);
        if (dev->flags & PCAP_IF_LOOPBACK) continue;  // Skip loopback devices

        // Open device in capture mode
        handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening device %s: %s\n", dev->name, errbuf);
            return -1;
        }

        // Set the channel (if necessary)
        // This step is specific to your wireless adapter and its capabilities

        // Set output file for saving captured packets
        pcap_dumper_t *dumpfile = pcap_dump_open(handle, filename);
        if (dumpfile == NULL) {
            fprintf(stderr, "Error opening output file %s\n", filename);
            return -1;
        }

        // Start capturing packets
        printf("Capturing on channel %d, saving to %s...\n", channel, filename);
        if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
            fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(handle));
            return -1;
        }

        pcap_dump_close(dumpfile);
        pcap_close(handle);
    }

    // Free the list of devices
    pcap_freealldevs(alldevs);
    return 0;
}
