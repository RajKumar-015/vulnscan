#include <stdio.h>
#include <string.h>

int main() {
    char buffer[2048];

    printf("Enter something: ");

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        /* Ensure null terminator is properly appended */
        while (*buffer == '\n') {
            buffer++;
        }

        printf("%*s", sizeof(buffer) - 1, buffer);
    }

    return 0;
}