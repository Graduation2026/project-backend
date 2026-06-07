#include <iostream>
#include <string>

void safe_cpp_func(const std::string &input) {
    if (input.length() < 16) {
        std::cout << "Safe C++: " << input << std::endl;
    } else {
        std::cout << "Input too long" << std::endl;
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        safe_cpp_func(argv[1]);
    }
    return 0;
}
