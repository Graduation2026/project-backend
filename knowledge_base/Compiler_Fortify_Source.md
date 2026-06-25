# Compiler Hardening - Fortify Source

Fortify Source (-D_FORTIFY_SOURCE=2) is a GCC feature that replaces standard unbounded string and memory copy functions (like strcpy, memcpy) with bounded checker wrappers (like __strcpy_chk) at compile-time and runtime. If the compiler can deduce the buffer size, it inserts runtime boundary verification checks that abort execution if an overflow occurs.

Enforced via gcc -O2 -D_FORTIFY_SOURCE=2.
