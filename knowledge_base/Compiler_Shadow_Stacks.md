# Compiler Hardening: Shadow Stacks

Shadow stacks provide backward-edge Control Flow Integrity by maintaining a separate, protected copy of return addresses. When a function is called, the return address is pushed onto both the regular stack and the shadow stack. Upon return, the hardware or software compares the two values — if they differ, a stack buffer overflow has corrupted the return address, and the program is terminated.

Hardware implementations: Intel Control-flow Enforcement Technology (CET) provides hardware shadow stacks via the `SHSTK` feature. ARM Pointer Authentication (PAC) signs return addresses cryptographically. Both have near-zero performance overhead since they operate in hardware.

Software implementations: GCC's `-mshstk` enables Intel CET shadow stacks. Clang's SafeStack (`-fsanitize=safe-stack`) separates the stack into a safe stack (for return addresses and spilled registers) and an unsafe stack (for buffers and local variables), so buffer overflows on the unsafe stack cannot reach return addresses.

Compile flags: `-fcf-protection=return` (GCC, for CET), `-fsanitize=safe-stack` (Clang, software-based), `-mbranch-protection=pac-ret` (ARM PAC). Kernel support is required for hardware shadow stacks.
