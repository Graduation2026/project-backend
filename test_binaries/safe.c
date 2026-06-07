#include <stdio.h>
#include <string.h>

void safe_c_func(const char *input) {
    char buf[16];
    if (input == NULL) return;
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("Safe C: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        safe_c_func(argv[1]);
    }
    return 0;
}
