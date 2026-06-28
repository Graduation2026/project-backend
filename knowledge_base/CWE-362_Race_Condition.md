# CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization (Race Condition)

Race conditions occur when the outcome of a program depends on the relative timing of two or more threads or processes accessing shared resources. In security contexts, race conditions can allow attackers to bypass access checks, corrupt shared data, or escalate privileges by exploiting the window between a check operation and the corresponding use operation (TOCTOU — Time of Check, Time of Use).

In compiled binaries, race conditions manifest as unsynchronized access to global variables, files, or shared memory regions. Signal handlers that modify global state are particularly dangerous because signals can interrupt code at arbitrary points.

CERT C Rule POS30-C: Use the readlink() function properly.
CERT C Rule SIG30-C: Call only asynchronous-safe functions within signal handlers.
CERT C Rule CON33-C: Avoid race conditions when using library functions.

Mitigation: (1) Use atomic operations or mutexes to synchronize shared resource access. (2) Minimize shared mutable state between threads. (3) Use `O_EXCL` flag with `open()` for exclusive file creation. (4) Replace TOCTOU-prone check-then-act patterns with atomic operations. (5) Use thread-safe library function variants (e.g., `strtok_r()` instead of `strtok()`).
