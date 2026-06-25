# CWE-120: Buffer Copy without Checking Size of Input (Classic Buffer Overflow)

This occurs when the program copies an input buffer to a destination buffer without verifying that the destination has enough space. Dangers of strcat/strcpy: The standard copy APIs append src to dest without bounds checking. If input exceeds target boundaries, it overflows memory, leading to corruption, program crashes, or code hijacking.

CERT C Rule STR31-C: Guarantee that storage for strings has sufficient space for character data and the null terminator.

Mitigation: Use bounded copy functions like strncat or snprintf, or perform explicit size checks before copying string characters.
