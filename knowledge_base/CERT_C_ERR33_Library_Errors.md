# CERT C Rule: ERR33-C — Detect and handle standard library errors

Many C standard library functions communicate errors through return values, errno, or both. Failing to check these error indicators leads to programs operating on invalid data, null pointers, or partial results — creating crash conditions, data corruption, or security vulnerabilities.

Critical functions that MUST have their return values checked:

Memory allocation: `malloc()`, `calloc()`, `realloc()` — return NULL on failure. Dereferencing NULL is undefined behavior (typically SIGSEGV, but can be exploited on systems without null page protection).

File I/O: `fopen()` returns NULL on failure. `fread()`/`fwrite()` return the count of items transferred (may be less than requested). `fclose()` returns EOF on failure (data may not be flushed).

String conversion: `strtol()`/`strtoul()` set errno on overflow/underflow. `atoi()` cannot report errors at all — prefer `strtol()`.

Network I/O: `recv()`/`send()` return -1 on error, 0 on connection close. Ignoring partial sends leads to data loss.

Best practice: Wrap error-prone calls in validation macros:
```c
#define CHECK_ALLOC(ptr) do { if (!(ptr)) { fprintf(stderr, "Allocation failed\n"); abort(); } } while(0)
char *buf = malloc(size);
CHECK_ALLOC(buf);
```
