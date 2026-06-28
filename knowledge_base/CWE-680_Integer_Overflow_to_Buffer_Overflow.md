# CWE-680: Integer Overflow to Buffer Overflow

CWE-680 describes the specific attack pattern where an integer overflow in a size calculation leads to a buffer overflow. The attacker provides input that causes an integer multiplication or addition to wrap around, resulting in a much smaller allocation than intended. Subsequent operations write data assuming the original (large) size, overflowing the undersized buffer.

Classic example: `size_t total = count * element_size;` — if `count` and `element_size` are attacker-controlled and their product exceeds `SIZE_MAX`, `total` wraps to a small value. The subsequent `malloc(total)` allocates a tiny buffer, but the code writes `count * element_size` bytes into it.

CERT C Rule INT30-C: Ensure that unsigned integer operations do not wrap.
CERT C Rule MEM35-C: Allocate sufficient memory for an object.

Mitigation: (1) Check for overflow BEFORE the multiplication: `if (count > SIZE_MAX / element_size) { error(); }`. (2) Use `calloc(count, element_size)` which performs the overflow check internally on most implementations. (3) Use compiler built-ins like `__builtin_mul_overflow()` for safe arithmetic. (4) Validate all size inputs against reasonable upper bounds before allocation.
