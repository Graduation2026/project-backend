# CWE-121: Stack-based Buffer Overflow

A stack-based buffer overflow condition exists when a buffer allocated on the stack has data written to it that is larger than the buffer. This corrupts the function's stack frame, overwrites local variables, and overwrites the saved instruction pointer (saved EBP/RBP and return EIP/RIP address) upon function return, enabling execution hijack.

Commonly caused by gets(), strcpy(), strcat(), or unchecked loop copies.

CERT C Rule ARR30-C: Formulate bounds checks on all buffers.

Mitigation: Avoid gets() entirely (use fgets instead). Ensure target buffer size is larger than the input data size using pre-conditions or bounds checks. Enable compiler protections like stack canaries (-fstack-protector).
