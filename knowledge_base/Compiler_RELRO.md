# Compiler Hardening - RELRO

RElocation Read-Only (RELRO) is a security feature to protect the Global Offset Table (GOT) from binary hijacking. Partial RELRO makes binary sections read-only after dynamic loading. Full RELRO (using GCC flags -Wl,-z,relro,-z,now) forces the dynamic linker to resolve all symbols at program startup and marks the entire GOT section as completely read-only, preventing attackers from overwriting GOT addresses to hook functions.
