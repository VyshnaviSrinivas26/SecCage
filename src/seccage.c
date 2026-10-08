#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <signal.h>
#include <errno.h>
#include <grp.h>
#include <sched.h>

#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/capability.h>

#include "policy.h"
#include "limits.h"


/* -------------------------------------------------
   SIGSYS handler
   ------------------------------------------------- */

void sigsys_handler(int sig, siginfo_t *info, void *context)
{
    const char message[] =
        "[SecCage] BLOCKED SYSCALL detected by seccomp\n";

    (void)sig;
    (void)info;
    (void)context;

    write(STDERR_FILENO, message, sizeof(message) - 1);

    _exit(1);
}


/* -------------------------------------------------
   Install SIGSYS handler
   ------------------------------------------------- */

void install_sigsys_handler()
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));

    action.sa_sigaction = sigsys_handler;

    sigemptyset(&action.sa_mask);

    action.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSYS, &action, NULL) == -1)
    {
        perror("[SecCage] SIGSYS handler failed");
        exit(1);
    }

    printf("[SecCage] SIGSYS handler installed\n");
}


/* -------------------------------------------------
   Network Namespace
   ------------------------------------------------- */

void setup_network_namespace()
{
    if (unshare(CLONE_NEWNET) == -1)
    {
        perror("[SecCage] Network namespace failed");
        exit(1);
    }

    printf("[SecCage] Network namespace created.\n");
}


/* -------------------------------------------------
   Drop Linux Capabilities
   ------------------------------------------------- */

void drop_capabilities()
{
    int cap;

    for (cap = 0; cap <= CAP_LAST_CAP; cap++)
    {
        prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
    }

    printf("[SecCage] Linux capabilities dropped\n");
}


/* -------------------------------------------------
   Drop Privileges
   ------------------------------------------------- */

void drop_privileges()
{
    if (setgroups(0, NULL) == -1)
    {
        perror("[SecCage] setgroups failed");
        exit(1);
    }

    if (setgid(65534) == -1)
    {
        perror("[SecCage] setgid failed");
        exit(1);
    }

    if (setuid(65534) == -1)
    {
        perror("[SecCage] setuid failed");
        exit(1);
    }

    printf(
        "[SecCage] Privileges dropped to UID 65534 (nobody)\n"
    );
}


/* -------------------------------------------------
   Convert syscall name to syscall number
   ------------------------------------------------- */

int get_syscall_number(const char *name)
{
    if (strcmp(name, "read") == 0)
        return SYS_read;

    if (strcmp(name, "write") == 0)
        return SYS_write;

    if (strcmp(name, "exit") == 0)
        return SYS_exit;

    if (strcmp(name, "exit_group") == 0)
        return SYS_exit_group;

    if (strcmp(name, "execve") == 0)
        return SYS_execve;

    if (strcmp(name, "brk") == 0)
        return SYS_brk;

    if (strcmp(name, "mmap") == 0)
        return SYS_mmap;

    if (strcmp(name, "munmap") == 0)
        return SYS_munmap;

    if (strcmp(name, "mprotect") == 0)
        return SYS_mprotect;

    if (strcmp(name, "arch_prctl") == 0)
        return SYS_arch_prctl;

    if (strcmp(name, "set_tid_address") == 0)
        return SYS_set_tid_address;

    if (strcmp(name, "set_robust_list") == 0)
        return SYS_set_robust_list;

    if (strcmp(name, "rseq") == 0)
        return SYS_rseq;

    if (strcmp(name, "getuid") == 0)
        return SYS_getuid;

    if (strcmp(name, "geteuid") == 0)
        return SYS_geteuid;

    /* File descriptor operations */

    if (strcmp(name, "dup") == 0)
        return SYS_dup;

    if (strcmp(name, "dup2") == 0)
        return SYS_dup2;

    /* Restricted operations */

    if (strcmp(name, "openat") == 0)
        return SYS_openat;

    if (strcmp(name, "socket") == 0)
        return SYS_socket;

    if (strcmp(name, "connect") == 0)
        return SYS_connect;

    return -1;
}


/* -------------------------------------------------
   Install Seccomp-BPF
   ------------------------------------------------- */

void install_seccomp(
    PolicyRule rules[],
    int rule_count
)
{
    struct sock_filter filter[100];

    int filter_count = 0;


    /* Check architecture */

    filter[filter_count++] =
        (struct sock_filter)BPF_STMT(
            BPF_LD | BPF_W | BPF_ABS,
            offsetof(struct seccomp_data, arch)
        );


    filter[filter_count++] =
        (struct sock_filter)BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K,
            AUDIT_ARCH_X86_64,
            1,
            0
        );


    filter[filter_count++] =
        (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K,
            SECCOMP_RET_KILL_PROCESS
        );


    /* Load syscall number */

    filter[filter_count++] =
        (struct sock_filter)BPF_STMT(
            BPF_LD | BPF_W | BPF_ABS,
            offsetof(struct seccomp_data, nr)
        );


    /* Apply policy rules */

    for (int i = 0; i < rule_count; i++)
    {
        int syscall_number =
            get_syscall_number(
                rules[i].syscall_name
            );


        if (syscall_number == -1)
        {
            printf(
                "[SecCage] Warning: unknown syscall %s\n",
                rules[i].syscall_name
            );

            continue;
        }


        if (rules[i].action == ACTION_ALLOW)
        {
            filter[filter_count++] =
                (struct sock_filter)BPF_JUMP(
                    BPF_JMP | BPF_JEQ | BPF_K,
                    syscall_number,
                    0,
                    1
                );


            filter[filter_count++] =
                (struct sock_filter)BPF_STMT(
                    BPF_RET | BPF_K,
                    SECCOMP_RET_ALLOW
                );
        }
        else
        {
            filter[filter_count++] =
                (struct sock_filter)BPF_JUMP(
                    BPF_JMP | BPF_JEQ | BPF_K,
                    syscall_number,
                    0,
                    1
                );


            filter[filter_count++] =
                (struct sock_filter)BPF_STMT(
                    BPF_RET | BPF_K,
                    SECCOMP_RET_TRAP
                );
        }
    }


    /* Default action */

    filter[filter_count++] =
        (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | EPERM
        );


    struct sock_fprog program;

    program.len = filter_count;

    program.filter = filter;


    /* Prevent privilege escalation */

    if (prctl(
            PR_SET_NO_NEW_PRIVS,
            1,
            0,
            0,
            0
        ) == -1)
    {
        perror("[SecCage] NO_NEW_PRIVS failed");
        exit(1);
    }


    printf("[SecCage] Installing seccomp-BPF...\n");


    /* Install filter */

    if (prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &program
        ) == -1)
    {
        perror("[SecCage] Seccomp installation failed");
        exit(1);
    }


    printf("[SecCage] Seccomp filter installed.\n");
}


/* -------------------------------------------------
   Main
   ------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf(
            "Usage: %s <policy-file> <program>\n",
            argv[0]
        );

        return 1;
    }


    const char *policy_file = argv[1];

    const char *program = argv[2];


    /* Load policy */

    PolicyRule rules[MAX_RULES];

    int rule_count = 0;


    if (load_policy(
            policy_file,
            rules,
            &rule_count
        ) != 0)
    {
        return 1;
    }


    printf(
        "[SecCage] Policy loaded: %d rules\n",
        rule_count
    );


    printf("[SecCage] Starting sandbox...\n");


    pid_t pid = fork();


    if (pid == -1)
    {
        perror("[SecCage] fork failed");
        return 1;
    }


    /* -------------------------------------------------
       CHILD PROCESS
       ------------------------------------------------- */

    if (pid == 0)
    {
        printf("[SecCage] Child process created.\n");


        /* Resource limits */

        apply_cpu_limit(2);

        apply_memory_limit(64);

        apply_file_limit(16);


        /* SIGSYS handler */

        install_sigsys_handler();


        /* Network namespace */

        setup_network_namespace();


        /* Drop privileges */

        drop_privileges();


        /* Drop capabilities */

        drop_capabilities();


        /* Install seccomp */

        install_seccomp(
            rules,
            rule_count
        );


        /* Execute target */

        printf(
            "[SecCage] Executing target: %s\n",
            program
        );


        char *args[] =
        {
            (char *)program,
            NULL
        };


        execvp(program, args);


        /* exec failed */

        perror("[SecCage] execvp failed");

        exit(1);
    }


    /* -------------------------------------------------
       PARENT PROCESS
       ------------------------------------------------- */

    printf("[SecCage] Waiting for target...\n");


    int status;


    if (waitpid(pid, &status, 0) == -1)
    {
        perror("[SecCage] waitpid failed");
        return 1;
    }


    /* Normal exit */

    if (WIFEXITED(status))
    {
        printf(
            "[SecCage] Target exited with status %d\n",
            WEXITSTATUS(status)
        );
    }


    /* Terminated by signal */

    else if (WIFSIGNALED(status))
    {
        printf(
            "[SecCage] Target terminated by signal %d\n",
            WTERMSIG(status)
        );
    }


    return 0;
}
