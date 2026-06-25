#ifndef SAFE_HPP
#define SAFE_HPP
#include <iostream>
#include <string>

inline int perform_hpp_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) result += i * 3;
        else result -= i * 2;
    }
    return result;
}

inline void process_user_hpp_string(const std::string& input) {
    std::string safe_dest = input.substr(0, 31);
    int calc = perform_hpp_calculations((int)safe_dest.length());
    std::cout << "HPP Processing (Safe): " << safe_dest << ", calc: " << calc << std::endl;
}
#endif
