# CERT C Rule: MEM30-C — Do not access freed memory (Use-After-Free Prevention)

Accessing memory after it has been freed leads to undefined behavior. The allocator may have returned that memory for a subsequent allocation, meaning the freed pointer now references a completely different object. If an attacker controls the replacement allocation, they control the data the program reads through the dangling pointer.

Dangerous patterns: (1) Freeing a struct member then accessing another member through the same pointer. (2) Freeing within a conditional branch but continuing to use the pointer afterward. (3) Freeing in one function while another function retains a reference. (4) Freeing a node in a linked list while iterating over it.

Prevention strategies:
```c
// Pattern 1: NULL after free
free(ptr);
ptr = NULL;  // Any subsequent access crashes immediately (NULL deref)

// Pattern 2: Safe-free macro
#define SAFE_FREE(p) do { free(p); (p) = NULL; } while(0)

// Pattern 3: Ownership semantics
// Only the "owner" of memory is allowed to free it.
// All other references are "borrowed" and must not outlive the owner.
```

Additional mitigations: Use ASAN (`-fsanitize=address`) which quarantines freed memory to detect UAF. Use smart pointers (`unique_ptr`, `shared_ptr`) in C++ to automate lifetime management.
