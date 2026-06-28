# CWE-415: Double Free

A double free vulnerability occurs when `free()` is called more than once on the same memory pointer without an intervening allocation. This corrupts the heap allocator's internal metadata (free lists), potentially allowing an attacker to achieve arbitrary write capabilities when the allocator reuses the corrupted chunk.

Exploitation typically involves: (1) The first `free()` returns the chunk to the free list, (2) The second `free()` adds it again, creating a cycle, (3) Subsequent `malloc()` calls return the same chunk twice, (4) The attacker controls one reference while the program trusts the other, enabling heap metadata corruption.

CERT C Rule MEM31-C: Free dynamically allocated memory when no longer needed.
CERT C Rule MEM30-C: Do not access freed memory.

Mitigation: (1) Set pointers to `NULL` immediately after `free()` — `free(ptr); ptr = NULL;`. (2) Use ownership semantics: only one component should be responsible for freeing any given allocation. (3) Implement a safe-free macro: `#define SAFE_FREE(p) do { free(p); (p) = NULL; } while(0)`. (4) Use ASAN during testing to detect double-free at runtime.
