#include <stdio.h>
#include <string.h>

void vuln_c_func(const char *input) {
    char buf[16];
    if (input == NULL) return;
    // CWE-120: Unbounded strcpy
    strcpy(buf, input);
    printf("Vuln C: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vuln_c_func(argv[1]);
    }
    return 0;
}
