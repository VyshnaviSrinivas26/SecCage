#include <stdio.h>
#include <fcntl.h>

int main()
{
    int fd[30];
    int i;

    printf("Trying to open 30 files...\n");

    for (i = 0; i < 30; i++)
    {
        fd[i] = open("secret.txt", O_RDONLY);

        if (fd[i] == -1)
        {
            perror("File open");
            printf("Failed at file number %d\n", i + 1);
            return 1;
        }

        printf("Opened file %d\n", i + 1);
    }

    return 0;
}
