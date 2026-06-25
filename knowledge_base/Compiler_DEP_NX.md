# Compiler Hardening - DEP/NX

Data Execution Prevention (DEP), also known as No-Execute (NX), is a hardware-supported memory protection. It marks data memory segments (such as the stack, heap, and BSS) as non-executable. If execution is redirected to shellcode stored in these data segments, the CPU immediately triggers an execution fault, preventing direct code execution payloads.
