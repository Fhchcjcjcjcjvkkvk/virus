#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#define EAPOL_TYPE 0x88

// Function to handle packets
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Filter for EAPOL packets (WPA/WPA2 handshake)
    if (packet[12] == EAPOL_TYPE) {
        printf("Captured EAPOL packet from BSSID: %s\n", (char*)user_data);
        
        // Save packet to file (pcap file) using user_data as the filename
        pcap_dump(user_data, pkthdr, packet);
    }
}

// Function to start packet capture
void start_capture(const char *interface, const char *bssid, const char *filename) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file for writing
    FILE *outfile = fopen(filename, "wb");
    if (!outfile) {
        perror("Error opening output file");
        exit(1);
    }

    // Open the network interface for sniffing in monitor/promiscuous mode
    handle = pcap_open_live(interface, 2048, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", interface, errbuf);
        exit(1);
    }

    // Set the BSSID filter if provided
    if (bssid != NULL) {
        struct bpf_program fp;
        char filter_exp[256];
        snprintf(filter_exp, sizeof(filter_exp), "ether host %s", bssid);
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
            exit(1);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
            exit(1);
        }
    }

    // Start capturing packets
    pcap_dumper_t *pcap_dump = pcap_dump_fopen(handle, outfile);
    pcap_loop(handle, 0, packet_handler, (u_char *)pcap_dump);

    // Clean up
    pcap_close(handle);
    fclose(outfile);
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s -b <bssid> --write <capture_file> -i <interface>\n", argv[0]);
        exit(1);
    }

    char *bssid = NULL;
    char *capture_file = NULL;
    char *interface = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0) {
            bssid = argv[i + 1];
        } else if (strcmp(argv[i], "--write") == 0) {
            capture_file = argv[i + 1];
        } else if (strcmp(argv[i], "-i") == 0) {
            interface = argv[i + 1];
        }
    }

    if (!bssid || !capture_file || !interface) {
        fprintf(stderr, "Missing required arguments!\n");
        exit(1);
    }

    printf("Capturing packets on interface %s...\n", interface);

    // Start packet capture
    start_capture(interface, bssid, capture_file);

    return 0;
}
