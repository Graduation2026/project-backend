# CWE-676: Use of Potentially Dangerous Function

CWE-676 covers the use of functions that are inherently unsafe due to their design — they cannot be used securely regardless of the calling context. These functions lack bounds checking, are vulnerable to format string attacks, or have been deprecated by standards bodies due to known security defects.

The most dangerous C functions include: `gets()` (no bounds checking, removed in C11), `strcpy()` (no length limit), `strcat()` (no remaining-space check), `sprintf()` (no output size limit), `scanf("%s")` (no input size limit), `mktemp()` (race condition in temporary file creation), `tmpnam()` (predictable filename generation).

CERT C Rule MSC33-C: Do not pass invalid data to the asctime() function.
CERT C Rule STR31-C: Guarantee that storage for strings has sufficient space.

Mitigation: Replace dangerous functions with safe alternatives: `gets()` → `fgets()`, `strcpy()` → `strlcpy()` or `strcpy_s()`, `strcat()` → `strlcat()` or `strcat_s()`, `sprintf()` → `snprintf()`, `scanf("%s")` → `scanf("%Ns")` with width, `mktemp()` → `mkstemp()`, `tmpnam()` → `tmpfile()`. Enable `-Wdeprecated` warnings.
