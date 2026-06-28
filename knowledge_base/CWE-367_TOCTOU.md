# CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition

TOCTOU is a specific class of race condition where a program first checks a condition (the "check"), then acts on the assumption that the condition still holds (the "use"). An attacker can modify the resource between the check and the use to bypass security controls.

Classic example in filesystem operations: a program calls `access()` to verify a user has permission to read a file, then calls `open()` to read it. Between these two calls, the attacker replaces the file with a symlink to `/etc/shadow`. The `access()` check passed on the original file, but `open()` follows the symlink.

CERT C Rule FIO01-C: Be careful using functions that use file names for identification.
CERT C Rule POS35-C: Avoid race conditions while checking for the existence of a symbolic link.

Mitigation: (1) Use file descriptors instead of filenames after initial open — operate on the fd, not the path. (2) Use `fstat()` on the fd instead of `stat()` on the path. (3) Use `O_NOFOLLOW` to prevent symlink following. (4) Use atomic operations where available: `open()` with `O_CREAT|O_EXCL` for exclusive creation. (5) Drop privileges before file operations when possible.
