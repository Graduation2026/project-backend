# Assembly Threat Auditing and Register Mechanics

Key registers: ESP/RSP (Stack Pointer pointing to the top of the stack), EBP/RBP (Base Frame Pointer pointing to the bottom of the stack frame), EAX/RAX (Accumulator register, holds return values and syscall codes).

Dangerous instructions: jmp esp (classic stack execution pivot), call eax (indirect function call vulnerable to hijack), int 0x80 / syscall (triggers kernel-level system trap calls).
