#ifndef VULN_H
#define VULN_H
#include <stdio.h>
#include <string.h>

static inline void vuln_header_func(const char *input) {
    char buf[16];
    if (input != NULL) {
        strcpy(buf, input);
        printf("Vuln Header: %s\n", buf);
    }
}
#endif
