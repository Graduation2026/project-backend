#ifndef VULN_H
#define VULN_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static inline int perform_header_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) result += i * 3;
        else result -= i * 2;
    }
    return result;
}

static inline void process_user_header_string(const char *input) {
    char dest[32];
    if (input == NULL) return;
    strcpy(dest, input); // Vulnerable (CWE-121)
    int calc = perform_header_calculations((int)strlen(dest));
    printf("Header Processing (Vuln): %s, calc: %d\n", dest, calc);
}
#endif
