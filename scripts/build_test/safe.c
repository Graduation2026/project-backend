#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Auxiliary calculations to simulate complexity
int perform_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) {
            result += i * 3;
        } else {
            result -= i * 2;
        }
    }
    return result;
}

// Bounded string copying (Safe version of string_manipulator)
void process_user_string(const char *input) {
    char dest[32];
    if (input == NULL) return;
    
    // Bounded copy using strncpy
    strncpy(dest, input, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';
    
    int calc = perform_calculations((int)strlen(dest));
    printf("Processing result (Safe): %s, calc: %d\n", dest, calc);
}

// Safe formatting (Safe version of logger_service)
void log_message(const char *msg) {
    if (msg == NULL) return;
    char log_buf[128];
    snprintf(log_buf, sizeof(log_buf), "LOG: %s\n", msg);
    printf("%s", log_buf);
}

// Safe memory allocation (Safe version of array_allocator)
int *allocate_integer_array(int count) {
    if (count <= 0 || count > 1000) {
        printf("Invalid allocation size request.\n");
        return NULL;
    }
    int *arr = (int *)malloc(count * sizeof(int));
    if (arr == NULL) {
        return NULL;
    }
    for (int i = 0; i < count; i++) {
        arr[i] = i * i;
    }
    return arr;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_user_string(argv[1]);
        log_message(argv[1]);
        int *data = allocate_integer_array(5);
        if (data) {
            printf("Data allocated successfully: %d\n", data[4]);
            free(data);
        }
    } else {
        printf("Usage: %s <input_string>\n", argv[0]);
    }
    return 0;
}
