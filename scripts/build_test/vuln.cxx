#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>

int perform_cpp_calculations(int val) {
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

void process_user_cpp_string(const char* input) {
    char dest[32];
    if (input == nullptr) return;
    // Unbounded string copy (CWE-121)
    std::strcpy(dest, input);
    
    int calc = perform_cpp_calculations((int)std::strlen(dest));
    std::cout << "CPP Processing result (Vuln): " << dest << ", calc: " << calc << std::endl;
}

void log_cpp_message(const char* msg) {
    if (msg == nullptr) return;
    // Vulnerable format string (CWE-134)
    std::printf(msg);
    std::printf("\n");
}

int* allocate_cpp_array(int count) {
    // Integer overflow in array allocation size calculation (CWE-190)
    int* arr = (int*)std::malloc(count * sizeof(int));
    if (arr == nullptr) {
        return nullptr;
    }
    for (int i = 0; i < count; i++) {
        arr[i] = i * i;
    }
    return arr;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        process_user_cpp_string(argv[1]);
        log_cpp_message(argv[1]);
        int* data = allocate_cpp_array(5);
        if (data) {
            std::cout << "CPP Data allocated: " << data[4] << std::endl;
            std::free(data);
        }
    } else {
        std::cout << "Usage: " << argv[0] << " <input_string>" << std::endl;
    }
    return 0;
}
