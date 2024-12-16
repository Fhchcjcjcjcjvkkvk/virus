#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NUM_WORDS 10
#define WORD_LENGTH 7
#define CHAR_SET "abcdegrfkdlANBSHJDO1245678?!"

// Function to generate a random word
void generate_word(char *word, int length) {
    int char_set_length = strlen(CHAR_SET);
    
    for (int i = 0; i < length; i++) {
        int random_index = rand() % char_set_length;
        word[i] = CHAR_SET[random_index];
    }
    word[length] = '\0';  // Null-terminate the word
}

int main() {
    // Seed the random number generator
    srand(time(NULL));

    // Array to store 10 words
    char word[NUM_WORDS][WORD_LENGTH + 1];

    // Generate 10 words and print them
    for (int i = 0; i < NUM_WORDS; i++) {
        generate_word(word[i], WORD_LENGTH);
        printf("%s\n", word[i]);
    }

    return 0;
}
