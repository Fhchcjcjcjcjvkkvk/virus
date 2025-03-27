#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <getopt.h>
#include <signal.h>
#include <math.h>
#include <float.h>
#include <ctype.h>

#define MAX_PASS_LEN 64
#define BSSID_LEN 6
#define MAX_SSID_LEN 32

typedef unsigned char byte;

// Struktura pro uchování handshake
typedef struct {
    byte anonce[32];
    byte snonce[32];
    byte mic[16];
    byte key_data[32];
} handshake_t;

// Funkce pro načítání handshake z pcap souboru
int read_pcap_handshake(const char *filename, handshake_t *handshake) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    int found = 0;

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Chyba při otevírání pcap souboru: %s\n", errbuf);
        return -1;
    }

    // Procházení paketů a hledání WPA handshake
    while ((packet = pcap_next(handle, &header)) != NULL) {
        if (found) break;
        // Detekce WPA2 handshake (v praxi bude nutné detekovat specifické pakety)
        if (/* podmínka pro detekci WPA handshake */) {
            memcpy(handshake->anonce, packet + 0x10, 32);  // Ukázka adresování, změňte podle skutečné struktury
            memcpy(handshake->snonce, packet + 0x30, 32);
            memcpy(handshake->mic, packet + 0x50, 16);
            found = 1;
        }
    }

    pcap_close(handle);
    return found ? 0 : -1;
}

// Funkce pro výpočet PMK z hesla a SSID
void calculate_pmk(const char *password, const char *ssid, byte *pmk) {
    const byte *ssid_bytes = (const byte *)ssid;
    const byte *password_bytes = (const byte *)password;

    PKCS5_PBKDF2_HMAC(password_bytes, strlen(password), ssid_bytes, strlen(ssid), 4096, EVP_sha1(), 32, pmk);
}

// Funkce pro ověření hesla pomocí PMK a handshake
int verify_password(const handshake_t *handshake, const byte *pmk) {
    unsigned char calculated_mic[16];
    
    // Vytvoření HMAC kontextu bez použití deprecated funkcí
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);  // Nový způsob inicializace
    HMAC_Init_ex(&ctx, pmk, 32, EVP_sha1(), NULL);
    HMAC_Update(&ctx, handshake->anonce, 32);
    HMAC_Update(&ctx, handshake->snonce, 32);
    HMAC_Final(&ctx, calculated_mic, NULL);
    HMAC_CTX_cleanup(&ctx);  // Nový způsob uvolnění kontextu

    // Porovnání MIC hodnot
    if (memcmp(handshake->mic, calculated_mic, 16) == 0) {
        return 1;  // Heslo je správné
    }
    return 0;  // Heslo není správné
}

// Funkce pro slovníkový útok
int dictionary_attack(const char *filename, const char *ssid, const handshake_t *handshake) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Nelze otevřít slovníkový soubor.\n");
        return -1;
    }

    char password[MAX_PASS_LEN];
    byte pmk[32];

    // Procházení slovníku
    while (fgets(password, MAX_PASS_LEN, file)) {
        password[strcspn(password, "\n")] = 0; // Odstranění nového řádku

        // Výpočet PMK pro aktuální heslo
        calculate_pmk(password, ssid, pmk);

        // Ověření hesla
        if (verify_password(handshake, pmk)) {
            printf("KEY FOUND! Heslo: %s\n", password);
            fclose(file);
            return 0;
        }
        printf("Trying Passphrase: %s\n", password);
    }

    printf("KEY NOT FOUND - Heslo nebylo nalezeno ve slovníku.\n");
    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    char *capture_file = NULL;
    char *wordlist_file = NULL;
    char *bssid = NULL;
    char *ssid = NULL;

    // Parsování příkazových argumentů
    int opt;
    while ((opt = getopt(argc, argv, "f:w:b:s:")) != -1) {
        switch (opt) {
            case 'f':
                capture_file = optarg;
                break;
            case 'w':
                wordlist_file = optarg;
                break;
            case 'b':
                bssid = optarg;
                break;
            case 's':
                ssid = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -f capture_file -w wordlist_file -b bssid -s ssid\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!capture_file || !wordlist_file || !ssid) {
        fprintf(stderr, "Musíte zadat capture soubor, slovníkový soubor a SSID.\n");
        exit(EXIT_FAILURE);
    }

    // Načítání handshake z pcap souboru
    handshake_t handshake;
    if (read_pcap_handshake(capture_file, &handshake) != 0) {
        fprintf(stderr, "Chyba při čtení handshake.\n");
        exit(EXIT_FAILURE);
    }

    // Provedení slovníkového útoku
    return dictionary_attack(wordlist_file, ssid, &handshake);
}
