#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main()
{
    int fd;
    int count = 0;

    printf("Testing file descriptor limit...\n");

    while (1)
    {
        fd = dup(STDOUT_FILENO);

        if (fd == -1)
        {
            perror("dup");
            break;
        }

        count++;

        printf("Created descriptor %d\n", fd);
    }

    printf("Total duplicated descriptors: %d\n", count);

    return 0;
}
