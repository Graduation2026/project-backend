# CWE-125: Out-of-bounds Read

An out-of-bounds read occurs when software reads data from a memory location that is outside the boundaries of the intended buffer. While this may not directly enable code execution, it can leak sensitive information (cryptographic keys, passwords, ASLR base addresses) that facilitates further exploitation.

The most famous example is Heartbleed (CVE-2014-0160), where OpenSSL read up to 64KB beyond buffer boundaries, leaking server private keys. In compiled binaries, OOB reads typically appear as array accesses with insufficient bounds checking, pointer dereferences past allocated regions, or string functions reading past null terminators.

CERT C Rule ARR30-C: Do not form or use out-of-bounds pointers or array subscripts.

Mitigation: (1) Validate all array indices against buffer sizes before access. (2) Use size-tracked buffer structures instead of raw pointers. (3) Return error codes instead of reading default/garbage values. (4) Enable AddressSanitizer to catch OOB reads during testing. (5) Implement canary values at buffer boundaries for runtime detection.
