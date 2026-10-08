#include <stdio.h>

int main()
{
    printf("Trying to open a file...\n");

    FILE *file = fopen("secret.txt", "r");

    if (file == NULL)
    {
        perror("File access");
        return 1;
    }

    printf("File opened successfully!\n");

    fclose(file);

    return 0;
}
