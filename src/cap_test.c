#include <stdio.h>
#include <unistd.h>

int main()
{
    printf("Running as UID: %d\n", getuid());
    printf("Capability drop test program running.\n");

    return 0;
}
