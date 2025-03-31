#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define MAX_SSID_LEN 32
#define MAX_PSK_LEN 64
#define MAX_PMK_LEN 32
#define EAPOL_TYPE 0x888e

typedef struct {
    char ssid[MAX_SSID_LEN];
    char bssid[18];
    int has_handshake;
} Network;

struct ether_header {
    u_char ether_dhost[6]; /* destination eth addr */
    u_char ether_shost[6]; /* source ether addr    */
    u_short ether_type;    /* packet type ID field */
};

void decrypt_password(const char *password, const char *ssid, unsigned char *pmk) {
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), (unsigned char *)ssid, strlen(ssid), 4096, MAX_PMK_LEN, pmk);
}

void list_networks(const char *pcap_file, Network *networks, int *network_count) {
    // Open the pcap file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int count = 0;
    int ssid_len;
    char ssid[MAX_SSID_LEN];

    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        struct ether_header *eth_hdr = (struct ether_header *)packet;
        if (ntohs(eth_hdr->ether_type) == EAPOL_TYPE) {
            u_char *bssid = eth_hdr->ether_shost; // Source MAC address as BSSID
            snprintf(networks[count].bssid, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

            // Extract SSID (this is simplified)
            int offset = sizeof(struct ether_header) + 2; // Offset to the EAPOL payload
            ssid_len = packet[offset + 1];
            memcpy(ssid, &packet[offset + 2], ssid_len);
            ssid[ssid_len] = '\0';
            snprintf(networks[count].ssid, MAX_SSID_LEN, "%s", ssid);

            networks[count].has_handshake = 1; // Assume handshake is present
            count++;
        }
    }

    *network_count = count;
    pcap_close(handle);
}

int process_handshake(const char *pcap_file, unsigned char *pmk) {
    // Open the pcap file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 0;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int eapol_count = 0;

    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        struct ether_header *eth_hdr = (struct ether_header *)packet;
        if (ntohs(eth_hdr->ether_type) == EAPOL_TYPE) {
            eapol_count++;
        }
    }

    pcap_close(handle);
    return eapol_count >= 1;
}

int main(int argc, char *argv[]) {
    if (argc != 4 || strcmp(argv[1], "-P") != 0) {
        printf("Usage: %s -P passwordlist.pwds eapol.pcap\n", argv[0]);
        return 1;
    }

    const char *password_file = argv[2];
    const char *pcap_file = argv[3];
    unsigned char pmk[MAX_PMK_LEN];

    Network networks[100];
    int network_count = 0;
    list_networks(pcap_file, networks, &network_count);

    printf("Available networks:\n");
    for (int i = 0; i < network_count; i++) {
        printf("BSSID: %s, SSID: %s, Notes: %s\n", networks[i].bssid, networks[i].ssid,
               networks[i].has_handshake ? "(Handshake)" : "");
    }

    printf("Select a network by entering the SSID: ");
    char selected_ssid[MAX_SSID_LEN];
    scanf("%s", selected_ssid);

    FILE *file = fopen(password_file, "r");
    if (!file) {
        printf("Error: Could not open password file %s\n", password_file);
        return 1;
    }

    printf("Analyzing %s...\n", password_file);

    char password[MAX_PSK_LEN];
    int total_passwords = 0;
    while (fgets(password, sizeof(password), file)) {
        total_passwords++;
    }
    rewind(file);

    printf("Starting...\n");

    int current_password_count = 0;
    while (fgets(password, sizeof(password), file)) {
        current_password_count++;
        password[strcspn(password, "\n")] = 0; // Remove newline character
        printf("\rTrying Passphrase: %s", password);
        fflush(stdout);
        decrypt_password(password, selected_ssid, pmk);

        printf("\n[*] Decrypting... (%d/%d passwords)\n", current_password_count, total_passwords);
        if (process_handshake(pcap_file, pmk)) {
            printf("KEY FOUND! [%s]\n", password);
            fclose(file);
            return 0;
        }
    }

    printf("KEY NOT FOUND\n");
    fclose(file);
    return 1;
}
