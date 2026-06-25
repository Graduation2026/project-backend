# CWE-787: Out-of-bounds Write

The software writes data past the end, or before the beginning, of the intended buffer. This can lead to heap corruption, stack variable overwrite, or system crash. Common in manual pointer arithmetic or custom memory copy loops without boundary assertions.

CERT C Rule ARR30-C: Do not form or use out-of-bounds pointers or array subscripts.

Mitigation: Always check boundaries. Use secure memory API wrappers. Validate that pointer offsets remain within the allocated memory bounds (e.g., bounds verification on array indexing).
