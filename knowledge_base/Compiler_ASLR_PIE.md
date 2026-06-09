# Compiler Hardening - ASLR and PIE

Address Space Layout Randomization (ASLR) is an OS security defense that randomizes the memory offsets where the stack, heap, and shared libraries are loaded. To enable this defense for the binary code segment itself, the program must be compiled as a Position Independent Executable (PIE) using GCC flags -fPIE -pie. This prevents attackers from relying on fixed, hardcoded function addresses in memory.
