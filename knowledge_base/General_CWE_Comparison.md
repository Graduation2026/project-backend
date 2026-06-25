# CWE-120 vs CWE-121

CWE-120 (Buffer Copy without Checking Size of Input) is the general flaw of performing a copy operation without verifying that the target buffer is large enough; it represents the copy action and can occur on the heap, stack, or static memory segments. CWE-121 (Stack-based Buffer Overflow) specifically designates that the destination buffer is located on the stack, which directly threatens stack-frame structures, saved registers (EBP/RBP), and the function return address.
