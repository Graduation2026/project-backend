# Compiler Hardening: AddressSanitizer (ASan)

AddressSanitizer (ASan) is a compile-time instrumentation tool that detects memory safety violations at runtime. It catches: heap/stack/global buffer overflows, use-after-free, use-after-return, use-after-scope, double-free, and memory leaks. ASan works by inserting redzones (poisoned memory regions) around every allocation and checking every memory access against a shadow memory map.

Usage: Compile and link with `-fsanitize=address`. Supported by GCC (4.8+), Clang (3.1+), and MSVC (2019+). Runtime overhead is approximately 2x slowdown and 2-3x memory usage, making it suitable for testing but not production deployment.

Shadow memory: ASan maps each 8 bytes of application memory to 1 byte of shadow memory. The shadow byte encodes whether each of the 8 bytes is accessible (0), partially accessible (1-7), or poisoned (negative values for different error types).

Detection capabilities: Stack buffer overflow (via stack redzones), heap buffer overflow (via heap redzones), global buffer overflow (via global redzones), use-after-free (via quarantine zones that delay reallocation), use-after-return (via fake stack frames), double-free (via quarantine tracking).

Compile flags: `-fsanitize=address -fno-omit-frame-pointer -O1` (recommended for useful stack traces with reasonable performance).
