#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define WORD_COUNT 1000    // Number of words to generate
#define MIN_WORD_LEN 3     // Minimum word length
#define MAX_WORD_LEN 12    // Maximum word length
#define OUTPUT_FILE "wordlist.txt" // Output file name

// Function to generate a random word
void generate_word(char *word, int min_len, int max_len) {
    int word_len = min_len + rand() % (max_len - min_len + 1); // Random length
    for (int i = 0; i < word_len; i++) {
        word[i] = 'a' + rand() % 26; // Generate a random letter
    }
    word[word_len] = '\0'; // Null-terminate the word
}

int main() {
    FILE *file = fopen(OUTPUT_FILE, "w");
    if (!file) {
        fprintf(stderr, "Error: Could not open output file.\n");
        return 1;
    }

    srand(time(NULL)); // Seed the random number generator

    char word[MAX_WORD_LEN + 1]; // Buffer for each word
    for (int i = 0; i < WORD_COUNT; i++) {
        generate_word(word, MIN_WORD_LEN, MAX_WORD_LEN);
        fprintf(file, "%s\n", word); // Write the word to the file
    }

    fclose(file);
    printf("Wordlist generated successfully in %s\n", OUTPUT_FILE);

    return 0;
}
