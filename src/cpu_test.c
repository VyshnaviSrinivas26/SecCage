#include <stdio.h>

int main()
{
    volatile unsigned long long count = 0;

    printf("CPU stress test started...\n");

    while (1)
    {
        count++;

        if (count % 100000000 == 0)
        {
            printf("CPU is still running...\n");
        }
    }

    return 0;
}
