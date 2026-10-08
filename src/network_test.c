#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main()
{
    printf("Trying to create a network socket...\n");

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        perror("Socket");
        return 1;
    }

    printf("Socket created successfully!\n");

    return 0;
}
