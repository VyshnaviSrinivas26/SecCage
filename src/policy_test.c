#include <stdio.h>

#include "policy.h"

int main()
{
    PolicyRule rules[MAX_RULES];
    int rule_count = 0;

    if (load_policy("policies/compute-only.policy",
                    rules,
                    &rule_count) != 0)
    {
        return 1;
    }

    printf("Policy loaded successfully.\n");
    printf("Number of rules: %d\n\n", rule_count);

    for (int i = 0; i < rule_count; i++)
    {
        printf("%-12s : %s\n",
               rules[i].syscall_name,
               rules[i].action == ACTION_ALLOW
                   ? "ALLOW"
                   : "DENY");
    }

    return 0;
}
