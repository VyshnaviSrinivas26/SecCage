#ifndef LIMITS_H
#define LIMITS_H

int apply_cpu_limit(int seconds);
int apply_memory_limit(int megabytes);
int apply_file_limit(int files);

#endif
