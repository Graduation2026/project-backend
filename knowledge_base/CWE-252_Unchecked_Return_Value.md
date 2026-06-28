# CWE-252: Unchecked Return Value

Many C library functions return values that indicate success, failure, or the number of bytes processed. When these return values are ignored, the program may continue operating on invalid data, fail silently, or enter an unexpected state that an attacker can exploit.

Critical functions whose return values must always be checked include: `malloc()` (returns NULL on failure), `fread()`/`fwrite()` (return count of items read/written), `snprintf()` (returns number of characters that would have been written), `open()`/`fopen()` (return -1/NULL on failure), `recv()`/`send()` (return bytes transferred or error).

CERT C Rule ERR33-C: Detect and handle standard library errors.
CERT C Rule EXP34-C: Do not dereference null pointers.

Mitigation: (1) Always check return values of allocation functions before dereferencing. (2) Check I/O function returns for short reads/writes and handle partial transfers. (3) Use compiler warnings (`-Wunused-result`) to catch ignored returns. (4) Use `__attribute__((warn_unused_result))` on custom functions that return error codes.
