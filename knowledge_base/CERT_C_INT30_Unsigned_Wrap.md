# CERT C Rule: INT30-C — Ensure that unsigned integer operations do not wrap

Unsigned integer overflow (wrap) in C is well-defined but dangerous: the result wraps modulo 2^N. This is exploitable when wrapped values are used for buffer sizes, loop counts, or security-critical comparisons. Attackers can cause allocations of size 0 or very small sizes, leading to subsequent buffer overflows.

Common vulnerable patterns: (1) `size = count * sizeof(element)` — multiplication can wrap. (2) `remaining = total - used` — subtraction can underflow if used > total. (3) `new_size = old_size + increment` — addition can wrap past SIZE_MAX.

Safe arithmetic checks (pre-condition validation):
```c
// Safe multiplication
if (count > 0 && element_size > SIZE_MAX / count) { error(); }
size_t total = count * element_size;

// Safe addition
if (a > SIZE_MAX - b) { error(); }
size_t sum = a + b;

// Safe subtraction
if (a < b) { error(); }
size_t diff = a - b;
```

GCC/Clang built-ins for overflow detection: `__builtin_add_overflow()`, `__builtin_sub_overflow()`, `__builtin_mul_overflow()`. These return true if the operation overflows and store the result in an output parameter.
