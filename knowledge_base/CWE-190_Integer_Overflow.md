# CWE-190: Integer Overflow or Wraparound

Occurs when an integer arithmetic operation produces a value outside the range that can be stored in the integer type. In C, if an integer overflow occurs during memory allocation calculations (like malloc(size * count)), it can wrap around to a very small number, causing malloc to allocate a tiny buffer while the program still writes the full amount of data, leading to a heap-based buffer overflow.

CERT C Rule INT30-C: Ensure that operations on unsigned integers do not wrap.

Mitigation: Check for overflow conditions before multiplication or addition, or use secure library safe math modules.
