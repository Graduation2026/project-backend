#ifndef VULN_HPP
#define VULN_HPP
#include <iostream>
#include <string>
#include <cstring>

inline int perform_hpp_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) result += i * 3;
        else result -= i * 2;
    }
    return result;
}

inline void process_user_hpp_string(const char* input) {
    char dest[32];
    if (input == nullptr) return;
    std::strcpy(dest, input); // Vulnerable (CWE-121)
    int calc = perform_hpp_calculations((int)std::strlen(dest));
    std::cout << "HPP Processing (Vuln): " << dest << ", calc: " << calc << std::endl;
}
#endif
