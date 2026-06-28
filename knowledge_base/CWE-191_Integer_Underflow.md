# CWE-191: Integer Underflow (Wrap or Wraparound)

Integer underflow occurs when an arithmetic operation produces a result smaller than the minimum representable value for the integer type. For unsigned integers, subtracting from zero wraps around to the maximum value (e.g., `0U - 1 = 4294967295` for 32-bit unsigned). For signed integers, the behavior is undefined per the C standard.

This is particularly dangerous when the underflowed value is used for buffer size calculations, loop bounds, or memory allocation sizes. An attacker who can cause an underflow in a size parameter can trick the program into allocating a tiny buffer while the program expects to write a large amount of data, leading to heap or stack buffer overflows.

CERT C Rule INT30-C: Ensure that unsigned integer operations do not wrap.
CERT C Rule INT32-C: Ensure that operations on signed integers do not result in overflow.

Mitigation: (1) Validate all arithmetic inputs before operations. (2) Check for underflow before subtraction: `if (a < b) { error(); } else { result = a - b; }`. (3) Use safe integer arithmetic libraries that detect overflow/underflow. (4) Use `size_t` correctly and validate it's non-zero before subtracting.
