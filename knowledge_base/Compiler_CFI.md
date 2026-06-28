# Compiler Hardening: Control Flow Integrity (CFI)

Control Flow Integrity is a security mechanism that restricts the set of valid targets for indirect control flow transfers (function pointers, virtual calls, return addresses). Without CFI, an attacker who corrupts a function pointer can redirect execution to any address. With CFI, the program validates that each indirect call target is a legitimate function entry point of the expected type.

CFI types: (1) **Forward-edge CFI**: Protects indirect calls and jumps. Validates that call targets match the expected function signature. Implemented via `-fsanitize=cfi` in Clang/LLVM. (2) **Backward-edge CFI**: Protects return addresses. Implemented via shadow stacks or return address signing (ARM PAC).

Clang CFI modes: `-fsanitize=cfi-vcall` (virtual calls), `-fsanitize=cfi-icall` (indirect function calls), `-fsanitize=cfi-derived-cast` (base-to-derived casts), `-fsanitize=cfi-unrelated-cast` (casts between unrelated types).

Limitations: CFI requires Link-Time Optimization (LTO) for full effectiveness. Dynamically loaded libraries need compatible CFI metadata. Performance overhead is typically 1-5%.

Compile flags: `-flto -fvisibility=hidden -fsanitize=cfi` (Clang). GCC offers `-fcf-protection=full` for Intel CET-based CFI.
