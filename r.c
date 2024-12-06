#include <stdio.h>

int main() {
    char name[50];

    // Ask the user for their name
    printf("Enter your name: ");
    scanf("%s", name);

    // Print a greeting message
    printf("Hello, %s! Welcome to the C programming world.\n", name);

    return 0;
}
