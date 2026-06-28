# CWE-77: Improper Neutralization of Special Elements used in a Command (Command Injection)

Command injection occurs when an application constructs system commands using unsanitized external input. If the input contains shell metacharacters (`;`, `|`, `&&`, backticks), the attacker can inject arbitrary commands that execute with the privileges of the vulnerable application.

This is especially dangerous in C/C++ programs that use `system()`, `popen()`, `exec*()` family functions, or any wrapper that invokes a shell interpreter. Unlike SQL injection which targets databases, command injection directly compromises the operating system.

CERT C Rule ENV33-C: Do not call system().

Mitigation: (1) Avoid `system()` and `popen()` entirely — use `exec*()` family with explicit argument arrays that bypass shell interpretation. (2) If shell invocation is unavoidable, implement strict input validation using allowlists of permitted characters. (3) Apply the principle of least privilege — run the process with minimal OS permissions. (4) Use `posix_spawn()` as a safer alternative that doesn't invoke a shell.
