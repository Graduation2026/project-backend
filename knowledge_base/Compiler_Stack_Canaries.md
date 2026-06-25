# Compiler Hardening - Stack Canaries

A compiler-enforced binary defense against stack smashing. The compiler places a random guard value (canary) on the stack frame between local buffers and the saved return pointer (EBP/RIP). Before returning, the function verifies that the canary value is unaltered. If an overflow has overwritten it, the program aborts immediately, preventing RIP hijack.

Enabled in GCC via -fstack-protector-strong or -fstack-protector-all.
