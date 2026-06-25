#include <iostream>
#include <string>
#include <vector>
#include <memory>

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

void process_user_cpp_string(const std::string& input) {
    std::string safe_dest = input.substr(0, 31);
    int calc = perform_cpp_calculations((int)safe_dest.length());
    std::cout << "CPP Processing result (Safe): " << safe_dest << ", calc: " << calc << std::endl;
}

void log_cpp_message(const std::string& msg) {
    std::cout << "LOG: " << msg << std::endl;
}

std::unique_ptr<int[]> allocate_cpp_array(int count) {
    if (count <= 0 || count > 1000) {
        std::cout << "Invalid count for array allocation." << std::endl;
        return nullptr;
    }
    std::unique_ptr<int[]> arr(new int[count]);
    for (int i = 0; i < count; i++) {
        arr[i] = i * i;
    }
    return arr;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        std::string input(argv[1]);
        process_user_cpp_string(input);
        log_cpp_message(input);
        auto data = allocate_cpp_array(5);
        if (data) {
            std::cout << "CPP Data allocated: " << data[4] << std::endl;
        }
    } else {
        std::cout << "Usage: " << argv[0] << " <input_string>" << std::endl;
    }
    return 0;
}
