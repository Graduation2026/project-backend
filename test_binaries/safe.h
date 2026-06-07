#ifndef SAFE_H
#define SAFE_H
#include <stdio.h>
#include <string.h>

static inline void safe_header_func(const char *input) {
    char buf[16];
    if (input != NULL) {
        strncpy(buf, input, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        printf("Safe Header: %s\n", buf);
    }
}
#endif
