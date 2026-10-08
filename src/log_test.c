#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void sigsys_handler(int sig, siginfo_t *info, void *context)
{
    const char message[] =
        "[Target] BLOCKED SYSCALL detected!\n";

    (void)sig;
    (void)info;
    (void)context;

    write(STDERR_FILENO, message, sizeof(message) - 1);

    _exit(1);
}

void install_handler()
{
    struct sigaction action;

    action.sa_sigaction = sigsys_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;

    sigaction(SIGSYS, &action, NULL);
}

int main()
{
    install_handler();

    printf("Trying to open a file...\n");
    fflush(stdout);

    FILE *file = fopen("secret.txt", "r");

    if (file == NULL)
    {
        perror("File open");
        return 1;
    }

    printf("File opened successfully!\n");

    fclose(file);

    return 0;
}
