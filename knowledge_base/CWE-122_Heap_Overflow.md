# CWE-122: Heap-based Buffer Overflow

A heap-based buffer overflow occurs when data is written beyond the boundaries of a dynamically allocated buffer (via `malloc()`, `calloc()`, `new`). Unlike stack overflows which corrupt return addresses, heap overflows corrupt heap metadata structures, adjacent heap objects, function pointers stored on the heap, or virtual table (vtable) pointers in C++ objects.

Exploitation techniques include: (1) Overwriting heap management metadata to achieve arbitrary write primitives, (2) Corrupting adjacent objects to redirect execution through modified vtable pointers, (3) Heap spraying to place attacker-controlled data at predictable addresses.

CERT C Rule MEM35-C: Allocate sufficient memory for an object.
CERT C Rule ARR30-C: Do not form or use out-of-bounds pointers.

Mitigation: (1) Always track allocated buffer sizes and validate before writing. (2) Use safe allocation wrappers that pair allocation size with the buffer. (3) Enable heap hardening: randomized chunk layout, guard pages between allocations. (4) Use `calloc()` instead of `malloc()` to prevent uninitialized memory leaks. (5) Employ ASAN (`-fsanitize=address`) to detect heap overflows during development.
