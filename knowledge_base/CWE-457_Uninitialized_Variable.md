# CWE-457: Use of Uninitialized Variable

Using an uninitialized variable reads whatever garbage data happens to be on the stack or heap at that memory location. This leads to unpredictable behavior: crashes, incorrect program logic, or information leaks where sensitive data from previous function calls is exposed through the uninitialized memory.

In compiled binaries, this manifests when local variables are declared but not assigned before use, when `malloc()` returns memory containing data from previous allocations, or when struct members are partially initialized. The behavior is formally undefined in C/C++, meaning the compiler can assume it never happens and optimize accordingly.

CERT C Rule EXP33-C: Do not read uninitialized memory.

Mitigation: (1) Always initialize variables at declaration: `int count = 0;`. (2) Use `calloc()` instead of `malloc()` to zero-initialize heap memory. (3) Use `memset()` to zero-initialize structures: `memset(&config, 0, sizeof(config))`. (4) Enable `-Wuninitialized` and `-Wall` compiler warnings. (5) Use static analysis tools that track initialization paths across branches.
