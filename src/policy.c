#include <stdio.h>
#include <string.h>

#include "policy.h"

int load_policy(const char *filename,
                PolicyRule rules[],
                int *rule_count)
{
    FILE *file = fopen(filename, "r");

    if (file == NULL)
    {
        perror("Could not open policy file");
        return -1;
    }

    char syscall_name[32];
    char action[16];

    *rule_count = 0;

    while (fscanf(file, "%31s %15s",
                  syscall_name, action) == 2)
    {
        if (*rule_count >= MAX_RULES)
        {
            printf("Too many policy rules.\n");
            fclose(file);
            return -1;
        }

        strcpy(rules[*rule_count].syscall_name,
               syscall_name);

        if (strcmp(action, "allow") == 0)
        {
            rules[*rule_count].action = ACTION_ALLOW;
        }
        else if (strcmp(action, "deny") == 0)
        {
            rules[*rule_count].action = ACTION_DENY;
        }
        else
        {
            printf("Unknown action: %s\n", action);
            fclose(file);
            return -1;
        }

        (*rule_count)++;
    }

    fclose(file);

    return 0;
}
