#include <stdio.h>
#include <sys/resource.h>

#include "limits.h"

int apply_cpu_limit(int seconds)
{
    struct rlimit limit;

    limit.rlim_cur = seconds;
    limit.rlim_max = seconds + 1;

    if (setrlimit(RLIMIT_CPU, &limit) == -1)
    {
        perror("[SecCage] CPU limit failed");
        return -1;
    }

    printf("[SecCage] CPU soft limit: %d seconds\n", seconds);
    printf("[SecCage] CPU hard limit: %d seconds\n", seconds + 1);

    return 0;
}


int apply_memory_limit(int megabytes)
{
    struct rlimit limit;

    rlim_t bytes = (rlim_t)megabytes * 1024 * 1024;

    limit.rlim_cur = bytes;
    limit.rlim_max = bytes;

    if (setrlimit(RLIMIT_AS, &limit) == -1)
    {
        perror("[SecCage] Memory limit failed");
        return -1;
    }

    printf("[SecCage] Memory limit: %d MB\n", megabytes);

    return 0;
}
int apply_file_limit(int files)
{
    struct rlimit limit;

    limit.rlim_cur = files;
    limit.rlim_max = files;

    if (setrlimit(RLIMIT_NOFILE, &limit) == -1)
    {
        perror("[SecCage] File limit failed");
        return -1;
    }

    printf("[SecCage] File descriptor limit: %d\n", files);

    return 0;
}
