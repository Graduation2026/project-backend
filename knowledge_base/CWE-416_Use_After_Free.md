# CWE-416: Use After Free

Referencing memory after it has been freed can lead to undefined behavior, program crash, or arbitrary code execution (especially if an attacker re-allocates that same heap block to a controlled object structure, altering virtual tables or function pointers).

CERT C Rule MEM30-C: Do not access freed memory.

Mitigation: After calling free(ptr), immediately assign ptr = NULL. This ensures any subsequent access fails immediately with a null pointer dereference rather than silently corrupting memory or enabling exploits.
