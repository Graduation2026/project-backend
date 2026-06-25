# CWE-242: Use of Inherently Dangerous Function

Certain legacy standard library functions like gets() cannot be used safely because they do not accept a maximum buffer size. They will copy input characters until a newline is found, making stack-based buffer overflows inevitable if user input exceeds the target array bounds.

CERT C Rule MSC24-C: Do not use gets().

Mitigation: Ban gets() completely. Replace with fgets() or secure C11 alternatives like gets_s().
