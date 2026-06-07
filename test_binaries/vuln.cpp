#include <iostream>
#include <cstring>

void vuln_cpp_func(const char *input) {
    char buf[16];
    if (input != nullptr) {
        // CWE-120: Unbounded strcpy in C++
        std::strcpy(buf, input);
        std::cout << "Vuln C++: " << buf << std::endl;
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vuln_cpp_func(argv[1]);
    }
    return 0;
}
