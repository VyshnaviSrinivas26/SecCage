#ifndef POLICY_H
#define POLICY_H

#define MAX_RULES 50

typedef enum
{
    ACTION_ALLOW,
    ACTION_DENY
} Action;

typedef struct
{
    char syscall_name[32];
    Action action;
} PolicyRule;

int load_policy(const char *filename,
                PolicyRule rules[],
                int *rule_count);

#endif
