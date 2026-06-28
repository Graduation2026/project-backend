# CWE-170: Improper Null Termination

Improper null termination occurs when a string buffer is not properly terminated with a null character (`\0`). Functions that operate on C-style strings (like `strlen()`, `printf()`, `strcmp()`) rely on null terminators to determine string boundaries. Without proper termination, these functions read past the buffer into adjacent memory, causing information leaks, crashes, or exploitable conditions.

Common causes include: using `strncpy()` which does NOT null-terminate when the source string length equals or exceeds `n`, manual string construction that forgets the terminating byte, and off-by-one errors in buffer size calculations that don't account for the null terminator.

CERT C Rule STR32-C: Do not pass a non-null-terminated character sequence to a library function that expects a string.

Mitigation: (1) Always explicitly null-terminate after `strncpy()` calls: `buf[sizeof(buf)-1] = '\0'`. (2) Prefer `snprintf()` which always null-terminates. (3) Use `strlcpy()` on BSD systems which guarantees null termination. (4) Account for the null terminator in all buffer size calculations (`sizeof(buf) - 1` for the data portion).
