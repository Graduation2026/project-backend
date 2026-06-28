# CWE-843: Access of Resource Using Incompatible Type (Type Confusion)

Type confusion occurs when a program accesses a resource (typically a memory object) using a type that is incompatible with the object's actual type. In C/C++, this happens through incorrect casts, union type punning, or when virtual dispatch tables (vtables) are corrupted, causing method calls to execute unintended code.

In compiled binaries, type confusion commonly manifests in: (1) C++ programs with complex inheritance hierarchies where downcasts skip type checks, (2) Interpreters and JIT compilers where type tags are manipulated, (3) Serialization/deserialization code that doesn't validate object types.

CERT C Rule EXP39-C: Do not access a variable through a pointer of an incompatible type.

Mitigation: (1) Use `dynamic_cast<>` in C++ instead of `static_cast<>` for downcasts — it performs runtime type checking. (2) Validate type tags before processing serialized objects. (3) Use tagged unions with explicit type discriminants. (4) Enable Control Flow Integrity (CFI) via `-fsanitize=cfi` to detect vtable corruption at runtime.
