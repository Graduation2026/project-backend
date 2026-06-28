# CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

CWE-119 is the parent category for all buffer-related vulnerabilities where software performs operations on a memory buffer without properly ensuring that read/write operations stay within the allocated boundaries. This encompasses buffer overflows (CWE-120), stack overflows (CWE-121), heap overflows (CWE-122), and out-of-bounds reads (CWE-125).

In compiled binaries, CWE-119 manifests through unsafe memory manipulation patterns: unbounded `memcpy()` calls, array indexing without bounds checks, pointer arithmetic that escapes allocated regions, and string operations that don't account for null terminators.

CERT C Rule ARR30-C: Do not form or use out-of-bounds pointers or array subscripts.
CERT C Rule ARR38-C: Guarantee that library functions do not form invalid pointers.

Mitigation: (1) Always validate buffer sizes before copy operations. (2) Use bounded alternatives: `strncpy()`, `snprintf()`, `memcpy_s()`. (3) Enable compiler protections: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`. (4) Use static analysis tools to detect potential overflows at compile time. (5) Employ AddressSanitizer (`-fsanitize=address`) during testing to catch runtime violations.
