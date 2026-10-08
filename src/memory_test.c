#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    size_t size = 128 * 1024 * 1024;

    printf("Trying to allocate 128 MB...\n");

    char *memory = malloc(size);

    if (memory == NULL)
    {
        printf("Memory allocation failed.\n");
        return 1;
    }

    memset(memory, 0, size);

    printf("128 MB allocated successfully!\n");

    free(memory);

    return 0;
}
