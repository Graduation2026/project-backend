# CWE-476: NULL Pointer Dereference

Occurs when a program dereferences a pointer that is expected to be valid but resolves to NULL. This causes immediate program crash or denial of service, and in some situations (such as kernel context or specific runtime environments), it can lead to arbitrary code execution.

CERT C Rule EXP34-C: Do not dereference null pointers.

Mitigation: Always check pointers for NULL before dereferencing, especially after memory allocations (malloc/calloc) and API library returns.
